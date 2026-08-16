# Redis for the ingestion stream

Redis carries a complete record of who talked to whom on the monitored network.
An open instance leaks exactly what the platform exists to protect, so it is
authenticated, loopback-published, and command-restricted.

```bash
docker compose up -d redis
```

## Why `users.acl` has no comments

Redis's ACL file parser accepts **one `user` directive per line and nothing
else**. Verified against `redis:7.4`:

| Written | Result |
|---|---|
| `# a comment` on line 1 | `Aborting Redis startup: users.acl:1 should start with user keyword` |
| backslash line continuation | `Aborting Redis startup: users.acl:2: Syntax error` |
| one `user` per line, no comments | starts cleanly |

An ACL error is fatal — Redis refuses to boot rather than run unauthenticated,
which is the right behaviour and also means a stray `#` takes the whole stream
down. That is why the documentation lives in this file instead.

## The roles

| User | Purpose | Key patterns |
|---|---|---|
| `default` | **disabled** — the unauthenticated superuser Redis ships with | — |
| `cs-producer` | capture side: publish flows, claim dedup keys, track processed pcaps | `cs:flows`, `cs:dedup:*`, `cs:pcap:processed` |
| `cs-consumer` | pipeline side: consume, acknowledge, reclaim, dead-letter | `cs:flows`, `cs:flows:dead` |
| `cs-observer` | dashboard and health checks | `cs:*`, read-only commands |
| `cs-admin` | maintenance — keep off application hosts | everything |

### An honest limitation

Redis key patterns apply per key, not per command, so `cs-consumer` holds
`+xadd` (needed for the dead-letter stream) across every key it can reach —
including `cs:flows`. **A compromised consumer could therefore append to the
ingest stream**, and an earlier draft of these docs claimed otherwise.

Redis 7 read-only key permissions (`%R~cs:flows`) do not solve it: `XREADGROUP`
is flagged as a *write* command because it mutates group state, so a read-only
pattern would break consumption entirely.

What the split does still buy:

- `cs-producer` cannot **read** the stream — no `XREADGROUP`, `XREAD`, or `XRANGE`.
- Neither role can `FLUSHALL`, `KEYS`, `CONFIG`, or touch anything outside `cs:*`.
- Both are separable and revocable without disturbing the other.

If append-isolation matters in your deployment, give the dead-letter writer its
own identity and drop `+xadd` from `cs-consumer`.

## Passwords

The values in `users.acl` are **development placeholders**. Generate real ones:

```bash
openssl rand -base64 32
```

Then supply them through the environment — never a committed file:

```bash
export INGESTION_REDIS_USERNAME=cs-producer
export INGESTION_REDIS_PASSWORD=...
```

`config/ingestion_policy.yaml` names those variables and never holds the values.

## `bind 0.0.0.0` is not a mistake

Inside a container, `0.0.0.0` means every interface *in that container's
network namespace* — not every interface on your machine.

Docker publishes a port by forwarding from the host to the container's bridge
address, so a container-loopback listener refuses every forwarded connection.
Binding `127.0.0.1` inside the container makes `127.0.0.1:6379:6379` fail with
`connection refused`, which looks exactly like Redis being down.

The real exposure controls are the host-side binding in `docker-compose.yml`
(`127.0.0.1:6379:6379`, never `6379:6379`) and the ACL above.

**Running Redis directly on a host instead? Change it back to `127.0.0.1`.**

## `user: redis` in compose, not `cap_add`

The image entrypoint checks `id -u`; when it is root it calls `setpriv` to drop
to the `redis` user, and `setpriv` needs `CAP_SETUID`. With `cap_drop: ALL`
that fails in a restart loop:

```
setpriv: setresuid failed: Operation not permitted
```

Starting as `redis` from PID 1 skips the drop entirely. Granting `SETUID` back
would also work and is strictly worse: the capability is never held rather than
held-then-surrendered.

## Verifying

```bash
docker compose up -d redis
docker logs cs-redis | tail -5          # expect "Ready to accept connections"
docker exec cs-redis redis-cli -u redis://cs-observer:PASSWORD@127.0.0.1:6379 ping
```
