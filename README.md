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

## What's Next

- **Phase 3** — Zeek network monitor installation and configuration (interface: ens5)
- **Phase 4** — Suricata IDS/IPS setup
- **Phase 5** — Project folder structure and Python environment
- **Phase 6** — Zeek watcher service
- **Phase 7** — Response Agent FastAPI service
- **Phase 8** — iptables persistence
- **Phase 9** — Log rotation
- **Phase 10** — Full pipeline test

---

## Notes

- t3.micro RAM (1GB) might get tight once Zeek and Suricata are both running. Will monitor and optimize worker configs if needed.
- Ubuntu 26.04 is a fresh release — keeping an eye out for any package naming differences compared to 22.04 docs.

---

*Prakanda Sapkota — Security/DevOps Engineer, Cyber Surakshya Project*