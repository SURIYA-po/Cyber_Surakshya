# Cyber Surakshya — Server Setup

This repo documents the setup process for the Cyber Surakshya threat detection infrastructure. I'm building this on an AWS EC2 t3.micro instance running Ubuntu 26.04 LTS. The end goal is a full security monitoring pipeline with Zeek, Suricata, Docker, and a FastAPI-based response agent tied into an AI-powered multi-agent detection system.

This README will grow as I work through each phase. For now, here's what got done today.

---

## Environment

- **Cloud**: AWS EC2 (Free Tier, 100 credits)
- **Instance**: t3.micro — 2 vCPU, 1GB RAM
- **OS**: Ubuntu 26.04 LTS (Resolute Raccoon)
- **Network Interface**: ens5
- **Access**: SSH via EC2 Instance Connect

---

## Phase 1 — Base Server Preparation (Completed)

Got the foundation sorted today. Nothing fancy, just making sure the server is clean, locked down, and ready for everything that comes next.

### What I did

**System update**
First thing before anything else — updated and upgraded all packages to make sure we're starting from a clean base with no outdated dependencies sitting around.

**Installed essential tools**
Grabbed the utilities we'll need throughout the project:
- `curl`, `wget` — for downloading stuff
- `git` — version control and repo cloning later
- `net-tools` — needed `ifconfig` to confirm the network interface
- `htop` — keeping an eye on CPU/RAM, especially important on a 1GB RAM instance
- `ufw` — firewall management
- `build-essential` — compilers for packages that need them
- `software-properties-common` — for adding PPAs later (Zeek needs this)

**Firewall setup with UFW**
Configured UFW before enabling it — important to add rules first or you lock yourself out over SSH. Opened:
- Port 22 (SSH)
- Ports 8000–8010 (FastAPI services)
- Port 4317 (OpenTelemetry monitoring)

**Hostname**
Set the static hostname to `cybersurakshya` so it's easy to identify in logs and the terminal prompt.

**Dedicated user**
Created a non-root user called `cybersurakshya` with sudo privileges. All services will run under this user going forward — not root.

**SSH key setup**
Copied the existing authorized keys from the default `ubuntu` user to `cybersurakshya`. Set correct permissions (700 on `.ssh`, 600 on `authorized_keys`). Key-based auth only.

**Network interface**
Confirmed the active interface is `ens5` — this will be used in both Zeek and Suricata configs in later phases.

---

## Phase 2 — Docker & Docker Compose Installation (Completed)

Got Docker properly set up today using the official Docker repository — not the outdated `docker.io` package that comes with Ubuntu. Also wired up Docker Compose v2 as a plugin rather than the old standalone binary.

### What I did

**Cleaned up old Docker versions**
The plan was to remove any old or unofficial Docker packages that might've been sitting around but it was clean.

**Added Docker's official GPG key**
Installed `ca-certificates` and `gnupg`, then pulled Docker's GPG key and stored it at `/etc/apt/keyrings/docker.gpg`. This lets apt verify that packages actually come from Docker and haven't been messed with.

**Added Docker's official apt repository**
Pointed apt at `download.docker.com` for the stable channel. Used `VERSION_CODENAME` from `/etc/os-release` so it picks the right repo for our Ubuntu version automatically.

**Installed Docker Engine**
Installed `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin`, and `docker-compose-plugin` all in one go. This gives us Docker Engine plus the v2 Compose plugin.

**Added users to docker group**
Added both `cybersurakshya` and `ubuntu` to the `docker` group so neither needs `sudo` for every docker command. Group change takes effect on next login.

**Enabled Docker on boot**
Enabled both `docker.service` and `containerd.service` via systemctl so Docker starts automatically on every reboot — important for a system that needs to always be running.

**Verified everything works**
Ran `docker run hello-world` and got the success message. Docker Engine and Docker Compose plugin both confirmed working.

---

## Phase 3 — Zeek Network Monitor Installation (Completed)

Got Zeek 8.0.5 installed and capturing live traffic. Ran into a couple of version-specific quirks since Zeek 8 is pretty new and most docs still reference older versions. Also hit a memory wall on the t3.micro which we worked around with swap — will upgrade the instance before the full pipeline test.

### What I did

**Added Zeek repository**
Zeek isn't in Ubuntu's default repos so added the official OpenSUSE-hosted Zeek apt repository along with its GPG key. Used the Ubuntu 22.04 repo since Zeek hasn't published a 26.04 one yet — works fine.

**Installed Zeek 8.0.5**
Straightforward apt install. Pulled in some mail-related dependencies we don't need — selected "No configuration" on the Postfix popup and moved on.

**Added Zeek to PATH**
Created `/etc/profile.d/zeek.sh` to permanently add `/opt/zeek/bin` to the system PATH so `zeek` and `zeekctl` work from anywhere without typing the full path.

**Configured node.cfg**
Set the network interface to `ens5` (our AWS EC2 interface) and kept it in standalone mode. Removed worker/lb_method lines to keep resource usage minimal on the t3.micro.

**Configured networks.cfg**
Added `172.31.0.0/16` as the local network range — this is the full AWS EC2 subnet range covering our availability zone.

**Configured zeekctl.cfg**
Disabled mail settings since we have no mail server. Confirmed log directory is set to `/opt/zeek/logs`.

**Configured JSON logging**
Zeek 8 handles JSON logging differently from older versions — `LogAscii::use_json` is no longer valid. Used the correct Zeek 8 approach with `LogAscii::json_timestamps` instead.

**Created 2GB swap file**
Zeek was getting OOM-killed on startup due to the t3.micro's 1GB RAM. Created a 2GB swap file at `/swapfile` and made it permanent via `/etc/fstab`. This gave enough headroom for Zeek to start cleanly.

**Deployed and verified**
Ran `zeekctl deploy` — Zeek came up with status `running`. Confirmed `/opt/zeek/logs/current/` is populated with `conn.log`, `dns.log` and others. Tailed `dns.log` after a ping to google.com and saw live JSON entries appearing.

**Created systemd service**
Created `/etc/systemd/system/zeek.service` so Zeek automatically deploys on every reboot via systemctl.

---

### Phase 4 — Suricata IDS/IPS Installation (Completed)
Got Suricata 8.0.3 installed and running alongside Zeek. Hit a couple of bumps with the new version and low RAM but worked through both. Both Zeek and Suricata are now running simultaneously on the t3.micro with the 2GB swap handling the memory pressure.

### What I did
Added OISF official PPA
Suricata isn't in Ubuntu's default repos so added the official OISF stable PPA. This gives us the latest stable release directly from the Suricata maintainers.
Installed Suricata 8.0.3
Clean apt install. Suricata 8 is a very fresh release — --version flag no longer works, use -V instead. Worth noting for anyone referencing older docs.
Configured suricata.yaml
Made three key changes to the main config:

Set HOME_NET to 172.31.0.0/16 to match our AWS EC2 subnet
Changed the af-packet interface from eth0 to ens5
Enabled eve-log JSON output and set community-id: true so Suricata alerts can be correlated with Zeek conn logs later in the pipeline
Disabled pcap-log to save disk space on our small instance

Downloaded ET Open ruleset
Installed suricata-update and pulled the latest Emerging Threats Open ruleset. Loaded 5016 signatures successfully.
Tested configuration
Ran suricata -T in test mode before starting the service — all 5016 signatures processed and config validated cleanly.
Fixed systemd startup timeout
Suricata 8 takes longer than systemd's default timeout to load rules on a t3.micro. Created /etc/systemd/system/suricata.service.d/timeout.conf and set TimeoutStartSec=300 to give it enough time. After the fix Suricata came up as active (running).
Verified eve.json output
Tailed /var/log/suricata/eve.json and confirmed stats entries are being written every few seconds in correct JSON format.

Set up weekly rule updates
Added a root crontab entry to run suricata-update every Monday at 3am and send SIGUSR2 to Suricata to reload rules without a full restart.

---

## Phase 5 — Project Folder Structure Setup (Completed)

Got the full project directory structure in place and the Python environment ready. This phase was mostly groundwork — setting up the scaffolding that Phases 6 and 7 will build on top of.

### What I did

Created project directories
Created the main project root at /opt/cybersurakshya/ with the following subdirectories:


zeek-watcher/ — will hold the log watcher service
response-agent/ — will hold the FastAPI response service
logs/ — centralized log storage for our services
config/ — configuration files including .env
docker/ — docker-related files for later phases


Set correct ownership
Transferred ownership of all directories to the cybersurakshya user recursively. All services will run as this user rather than root.

Created Python virtual environment
Ubuntu 26.04 ships Python 3.14 but doesn't include the venv module by default — had to install python3.14-venv separately first. Created the venv at /opt/cybersurakshya/venv/ owned by the cybersurakshya user.

Installed core Python packages
Installed all packages our services will need into the venv:

PackageVersionPurposefastapi0.136.3Response Agent API frameworkuvicorn0.49.0ASGI server for FastAPIredis8.0.0Redis client for inter-service messagingpsycopg2-binary2.9.12PostgreSQL database driverpython-dotenv1.2.2Loading .env config fileswatchdog6.0.0File system monitoring for Zeek watcherrequests2.34.2HTTP client for forwarding logspydantic2.13.4Data validation for API modelssqlalchemy2.0.50ORM for database interactions

Created .env config file
Created /opt/cybersurakshya/config/.env with placeholder values for Redis URL, PostgreSQL URL, Response Agent port, and log directory. Set permissions to 600 (owner read/write only) so sensitive values are protected.

- - - 

### Phase 6 — Zeek Watcher Service (Completed)

Got the Zeek watcher service running. This is the bridge between Zeek's raw network logs and the AI detection pipeline — it tails conn.log in real time, parses each new flow as JSON, and forwards it to the Detection Agent API. Hit a permissions issue with Zeek 8's log layout that took some digging to fix.

What the Zeek Watcher does


Watches /opt/zeek/spool/zeek/conn.log for new lines in real time using the watchdog library
Parses each new line as JSON and extracts key network flow fields: id.orig_h, id.resp_h, id.orig_p, id.resp_p, proto, duration, orig_bytes, resp_bytes, conn_state, orig_pkts, resp_pkts
Forwards each flow as a POST request to the Detection Agent API at http://localhost:8001/detect


## What I did

Created watcher.py
Wrote the watcher script at /opt/cybersurakshya/zeek-watcher/watcher.py using the watchdog library's FileSystemEventHandler. The script:


Opens conn.log and seeks to the end on startup so it only reads new entries
On every file modification event, reads new lines and parses them as JSON
Extracts only the agreed feature fields and POSTs them to the Detection Agent
Logs all activity to /opt/cybersurakshya/logs/watcher.log
Handles JSON parse errors and connection failures gracefully without crashing


Used sudo tee with a heredoc instead of nano to write the script — EC2 Instance Connect's terminal window is too small for pasting long scripts into nano cleanly.

Fixed Zeek 8 log path
Zeek 8 stores active logs at /opt/zeek/spool/zeek/ — the /opt/zeek/logs/current/ path is just a symlink pointing there. The watcher script uses the symlink path which resolves correctly.

Fixed permissions
The cybersurakshya user couldn't read Zeek's log files because they're owned by the zeek group. Fixed by adding cybersurakshya to the zeek group:

sudo usermod -aG zeek cybersurakshya

Created systemd service
Created /etc/systemd/system/zeek-watcher.service so the watcher starts automatically on boot after the zeek service is up. Service runs as the cybersurakshya user using the project venv.

Verified
Service shows active (running). Watcher log confirms it started and is tailing conn.log. Forwarding warnings to Detection Agent are expected at this stage — the Detection Agent gets built in Phase 7.

- - - 

### Phase 7 — Response Agent FastAPI Service (Completed)

Got the Response Agent running as a FastAPI service on port 8000. This is the enforcement arm of the pipeline — it receives block/unblock commands and executes them as real iptables rules on the server. Tested all endpoints manually with curl and confirmed iptables rules are being added and removed correctly.

What the Response Agent does

The Response Agent is a FastAPI web service that acts as the action executor for the Cyber Surakshya pipeline. When the Decision Agent determines a threat is real, it sends commands here:


POST /response/block-ip — adds an iptables DROP rule for the given IP
POST /response/unblock-ip — removes the iptables DROP rule
GET /response/active-blocks — returns list of currently blocked IPs from iptables
POST /response/add-suricata-rule — appends a rule to local.rules and reloads Suricata
POST /response/notify — logs notifications and optionally POSTs to a webhook URL
GET /health — returns service status
Redis subscriber thread — listens on channel:response_command for automated commands from the Decision Agent


## What I did

Created main.py
Wrote the full FastAPI application at /opt/cybersurakshya/response-agent/main.py. Used sudo tee with heredoc again to avoid nano terminal overflow issues on EC2 Instance Connect.

Key implementation details:


Runs as root (required for iptables access)
Loads config from /opt/cybersurakshya/config/.env via python-dotenv
All actions logged to /opt/cybersurakshya/logs/response-agent.log
Redis subscriber runs as a daemon thread on startup — handles Redis being unavailable gracefully without crashing
Webhook URL is optional — read from .env, skipped if empty


Created systemd service
Created /etc/systemd/system/response-agent.service running uvicorn on 0.0.0.0:8000. Service runs as root for iptables access and auto-restarts on failure.

Tested all critical endpoints


/health → {"status":"ok","service":"response-agent"} (done)
/response/block-ip with 10.0.0.99 → rule appeared in iptables INPUT chain (done)
/response/unblock-ip with 10.0.0.99 → rule removed from iptables cleanly (done)

--- 




## What's Next

- **Phase 6** — Zeek watcher service
- **Phase 7** — Response Agent FastAPI service
- **Phase 8** — iptables persistence
- **Phase 9** — Log rotation
- **Phase 10** — Full pipeline test

---

### Phase 8 — iptables Persistence (Completed)

This phase had an unexpected conflict but we worked around it cleanly. The standard iptables-persistent package conflicts with UFW on Ubuntu 26.04 — installing one removes the other. We solved it with a custom save/restore approach that integrates better with our Response Agent anyway.

What happened

iptables-persistent conflict
Attempted to install iptables-persistent for automatic iptables rule persistence across reboots. The package manager removed UFW as a conflicting dependency. Since UFW is our primary firewall managing SSH and service ports, we immediately reinstalled UFW and restored all rules:


Port 22 (SSH)
Ports 8000–8010 (FastAPI services)
Port 4317 (OpenTelemetry monitoring)


Custom persistence approach
Instead of fighting the package conflict, built a lightweight custom solution:

restore-blocks.sh — reads /opt/cybersurakshya/config/blocked-ips.txt on boot and re-applies iptables DROP rules for each saved IP. Runs as a oneshot systemd service (restore-blocks.service) that fires after network is up on every boot.

save-block.sh — called when an IP is blocked. Appends the IP to blocked-ips.txt if not already present. Prevents duplicates with a grep check.

remove-block.sh — called when an IP is unblocked. Removes the IP from blocked-ips.txt using sed in-place edit.

Tested persistence
Blocked test IP 10.0.0.55 via the Response Agent, saved it with save-block.sh, confirmed it appears in blocked-ips.txt. On next reboot restore-blocks.service will re-apply the DROP rule automatically.

## TODO


Update response-agent/main.py block/unblock endpoints to call save-block.sh and remove-block.sh automatically — currently requires manual call after blocking
This will make persistence fully seamless and transparent to the Decision Agent


---

### Phase 9 — Log Rotation and Disk Management (Completed)

 Set up log rotation for all three log sources — Zeek, Suricata, and our own services. On a small EBS volume this is critical — without rotation logs will fill the disk within days under active traffic.

## What I did

Zeek log rotation
Created /etc/logrotate.d/zeek to rotate logs daily, keep 7 days, compress old logs, and run zeekctl rotate after each rotation so Zeek reopens its log files cleanly. Old logs beyond 7 days are automatically removed.

Suricata eve.json rotation
Created /etc/logrotate.d/suricata to rotate eve.json daily, keep 14 days (longer than Zeek since alerts are more valuable to keep), and send SIGHUP to Suricata after rotation so it reopens the file without a full restart.

Response Agent and Watcher log rotation
Created /etc/logrotate.d/cybersurakshya to rotate all logs under /opt/cybersurakshya/logs/ daily, keep 7 days, and restart zeek-watcher and response-agent services after rotation so they reopen their log file handles.

Zeek archive cleanup cron job
Added a root cron job to run at 2am daily:

find /opt/zeek/logs/ -type f -name "*.log*" -mtime +30 -delete

This cleans up Zeek's archived log directory beyond 30 days as a second layer of disk protection.

Tested all configs
Ran logrotate --debug on all three configs — all validated cleanly. Both response-agent.log and watcher.log were found and considered for rotation. No errors on any config.

---

## Notes

- t3.micro RAM (1GB) might get tight once Zeek and Suricata are both running. Will monitor and optimize worker configs if needed.
- Ubuntu 26.04 is a fresh release — keeping an eye out for any package naming differences compared to 22.04 docs.
- Zeek 8.0.5 has breaking changes from older versions — watch out if referencing any pre-v7 docs
- t3.micro RAM is tight with swap as a workaround — planning to upgrade to t3.small before Phase 10 full pipeline test
- Suricata 8.0.3 has some breaking changes from older versions — --version flag removed, watch out for outdated docs
- Both Zeek and Suricata running simultaneously on t3.micro with 2GB swap — stable for now but will upgrade to t3.small before full pipeline test in Phase 10
- community-id enabled in both Zeek and Suricata — this is important for correlating events across both tools later
- Python 3.14 is the default on Ubuntu 26.04 — venv package needs to be installed separately unlike older Ubuntu versions
- .env file is locked to cybersurakshya user only — never commit this file to git
- Service runs as root intentionally — iptables requires root privileges. This is acceptable since it's an internal service not exposed to the internet
- Redis warning on startup is expected — Redis isn't installed yet. The subscriber thread catches the exception and logs a warning without crashing the service
- Webhook URL is empty in .env for now — can be pointed at a Slack/Teams webhook later for real notifications
- iptables-persistent and ufw are mutually exclusive on Ubuntu 26.04 — don't try to install both
- UFW rules are already persistent across reboots by default — only the dynamic iptables rules from our Response Agent needed the custom persistence solution
- blocked-ips.txt should be backed up periodically — it's the source of truth for all active blocks
- Logrotate runs automatically via system cron daily — no manual steps needed
- delaycompress is set on all configs so the most recent rotated log stays uncompressed for easy reading
- Suricata gets 14 days retention vs 7 for others — alerts are forensic evidence and worth keeping longer
- The 30-day Zeek archive cleanup is a safety net on top of the 7-day logrotate rotation



---

*Prakanda Sapkota — Security/DevOps Engineer, Cyber Surakshya Project*