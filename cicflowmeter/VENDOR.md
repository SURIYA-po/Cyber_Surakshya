# Vendored: cicflowmeter

This directory is a **vendored copy** of a third-party package, tracked as
ordinary files in this repository. It is not a git submodule.

| | |
|---|---|
| Upstream | https://github.com/hieulw/cicflowmeter |
| Vendored at commit | `5916fdd9f6e26c3110ebf3081b37f848bd56fd15` |
| Upstream branch | `master` |
| Local modifications | yes — see below |

## Why vendored rather than a submodule

The directory used to be recorded in the parent repository as a **gitlink**
(mode `160000`) pointing at commit `5916fdd`, but there was no `.gitmodules`
file and `.gitignore` contained `cicflowmeter/*`. A fresh `git clone` therefore
produced an empty `cicflowmeter/` directory with no way to populate it, and
`ingestion/flows/pcap_processor.py` failed at
`from cicflowmeter.sniffer import create_sniffer`.

Restoring it as a proper submodule would not have worked either, because the
local modification below **cannot be pushed** to the upstream repository. A
submodule pointer can only reference a commit that exists upstream, so no
pointer can reproduce the working state. Vendoring is the only structure a
fresh clone can reproduce.

## Local modifications

### `src/cicflowmeter/sniffer.py` — BPF filter removed

Upstream passes `filter="ip and (tcp or udp)"` to both `AsyncSniffer` calls.
scapy compiles a BPF filter string by shelling out to **`tcpdump`**, which is
not installed on Windows. With the filter present, `create_sniffer` raises
before reading a single packet, so `PcapProcessor` logs `pcap_extract_failed`
for every capture file and the live pipeline silently receives no flows —
capture appears healthy while producing nothing.

Non-IP and non-TCP/UDP packets are dropped by `FlowSession.process` anyway, so
removing the filter costs a little parsing work and changes no output.

**Do not re-add the filter** without guaranteeing `tcpdump` on every target
host.

## Updating from upstream

The pre-vendoring git history is preserved locally in `.git-upstream/`
(gitignored, not deleted). To pull upstream changes:

```bash
cd cicflowmeter
mv .git-upstream .git          # restore the nested repository
git fetch origin
git log --oneline HEAD..origin/master
# review, merge, re-apply the patch above, then:
mv .git .git-upstream
```

The local patch is also saved beside this file as `local-changes.patch` and can
be re-applied with `git apply cicflowmeter/local-changes.patch`.
