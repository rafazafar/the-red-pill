# the-red-pill

This repository contains a Bash-first DevOps investigation and migration toolkit: aDevOps.  
It is designed to fully understand everything running on a Linux server when given remote access (IP, user, password, or key). The goal is to produce a complete inventory and migration plan so a developer can move an unknown piece of software to a new host.

This file: [README.md](README.md)

## Goals

- Enumerate installed packages (system and language-level).
- Discover running services, hosted applications, and network listeners.
- Extract configuration files, data locations, and init/startup mechanisms.
- Identify external dependencies (databases, caches, message brokers, DNS, certs).
- Package artifacts and produce a migration checklist and scripts.
- Operate using only portable Bash + common GNU/Linux userland tools.

## Design principles

- Bash-only: prefer POSIX/Bash and common CLI tools (ssh, rsync, tar, scp, scp/sshpass when necessary).
- Non-invasive: data collection is read-only unless explicitly asked to perform exports/dumps.
- Reproducible outputs: produce structured text files and tarballs for later consumption.
- Security-aware: avoid exfiltrating secrets unless user consents; document secret locations.

## Prerequisites (investigator host)

- bash, ssh, scp, rsync, tar, gzip, jq (optional but recommended), sshpass (optional)
- network connectivity to target host(s)
- credentials (password or ssh private key)

## What it collects

- System info: uname, /etc/os-release, kernel, uptime.
- Users & groups: /etc/passwd, /etc/group, sudoers, authorized_keys.
- Installed packages:
  - Debian/Ubuntu: dpkg -l / apt list --installed
  - RHEL/CentOS: rpm -qa / yum/dnf list installed
  - Alpine: apk info
- Language packages: pip freeze, npm ls --global --depth=0, gem list, pipx, go binaries, cargo packages (where present).
- Services & startup:
  - systemd units (systemctl list-units --type=service --all)
  - SysV init scripts (/etc/init.d)
  - crontab entries (root and users)
  - rc.local, /etc/rc\*.d
- Running processes: ps aux, netstat -tulpen or ss -tulpen
- Listening ports and associated binaries
- Containers: docker ps, docker inspect, podman, kubelet hints
- Filesystem inventory: /opt, /usr/local, /srv, /var/www, web roots, mounted volumes
- Databases: discovered services (mysql/mariadb, postgresql, mongodb) and instructions to dump
- Certificates: /etc/letsencrypt, /etc/ssl, application cert files
- Logs: /var/log, journalctl --no-pager (sample)
- Configuration files for discovered apps
- Packageable artifacts: dirs with app binaries, virtualenvs, node_modules, static assets

## Output format

- report/<timestamp>/system-info.txt
- report/<timestamp>/packages/{system,python,node,ruby}.txt
- report/<timestamp>/services.txt
- report/<timestamp>/processes.txt
- report/<timestamp>/listening-ports.txt
- report/<timestamp>/filesystems.txt
- report/<timestamp>/collected-configs/\*.tar.gz
- report/<timestamp>/migration-plan.md

## Usage examples

Basic inventory using SSH key:

```bash
# inventory.sh <user>@<host> [ssh_opts...]
./inventory.sh alice@10.0.0.5 -i ~/.ssh/id_rsa
```
