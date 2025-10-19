#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: $0 <user@host> [ssh options]

Collects an extensive inventory from a remote Linux host to aid in migrations.
USAGE
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

target="$1"
shift

ssh_cmd=(ssh -o BatchMode=no)
scp_cmd=(scp)
while [[ $# -gt 0 ]]; do
  ssh_cmd+=("$1")
  scp_cmd+=("$1")
  shift
done

ssh_cmd+=("$target")

timestamp="$(date -u +%Y%m%d-%H%M%S)"
report_dir="report/$timestamp"
mkdir -p \
  "$report_dir"/packages \
  "$report_dir"/manifests \
  "$report_dir"/configs \
  "$report_dir"/applications \
  "$report_dir"/databases \
  "$report_dir"/network

log() {
  printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"
}

remote_exec() {
  local script
  if [[ $# -gt 0 ]]; then
    script="$1"
  else
    script=$(cat)
  fi
  {
    printf '%s\n' 'set -euo pipefail'
    printf '%s\n' "$script"
  } | "${ssh_cmd[@]}" "bash" "-s"
}

collect_system_info() {
  log "Collecting system information"
  remote_exec <<'EOF' > "$report_dir/system-info.txt"
printf "Hostname: %s\n" "$(hostname)"
printf "Kernel: %s\n" "$(uname -srv)"
printf "Uptime: %s\n" "$(uptime -p 2>/dev/null || uptime)"
echo "--- /etc/os-release ---"
cat /etc/os-release 2>/dev/null
echo "--- lsb_release ---"
lsb_release -a 2>/dev/null || true
echo "--- /proc/cpuinfo (top) ---"
grep -m 25 "" /proc/cpuinfo 2>/dev/null
echo "--- Memory ---"
free -m 2>/dev/null
echo "--- Disks ---"
lsblk -f 2>/dev/null
EOF
}

collect_users_groups() {
  log "Collecting users and groups"
  remote_exec <<'EOF' > "$report_dir/users-groups.txt"
echo "--- /etc/passwd ---"
cat /etc/passwd
echo "--- /etc/group ---"
cat /etc/group
echo "--- sudoers ---"
cat /etc/sudoers 2>/dev/null
for d in /etc/sudoers.d; do
  [ -d "$d" ] || continue
  echo "--- $d ---"
  ls "$d"
done
echo "--- Authorized keys ---"
find /home /root -maxdepth 2 -name authorized_keys -print 2>/dev/null | while read -r f; do
  echo "== $f =="
  cat "$f"
done
EOF
}

collect_packages() {
  log "Collecting package inventories"
  remote_exec <<'EOF' > "$report_dir/packages/system.txt"
if command -v dpkg >/dev/null; then
  dpkg -l
elif command -v rpm >/dev/null; then
  rpm -qa
elif command -v apk >/dev/null; then
  apk info
else
  echo "No known system package manager detected"
fi
EOF

  remote_exec <<'EOF' > "$report_dir/packages/python.txt" || true
if command -v pip >/dev/null; then pip freeze 2>/dev/null; fi
if command -v pip3 >/dev/null; then pip3 freeze 2>/dev/null; fi
if command -v python >/dev/null; then python -m pip list --format=freeze 2>/dev/null; fi
EOF

  remote_exec <<'EOF' > "$report_dir/packages/node.txt" || true
if command -v npm >/dev/null; then npm ls --global --depth=0 2>/dev/null; fi
if command -v yarn >/dev/null; then yarn global list 2>/dev/null; fi
if command -v bun >/dev/null; then bun pm ls 2>/dev/null; fi
EOF

  remote_exec <<'EOF' > "$report_dir/packages/ruby.txt" || true
if command -v gem >/dev/null; then gem list 2>/dev/null; fi
EOF

  remote_exec <<'EOF' > "$report_dir/packages/pipx.txt" || true
if command -v pipx >/dev/null; then pipx list 2>/dev/null; fi
EOF

  remote_exec <<'EOF' > "$report_dir/packages/go.txt" || true
if command -v go >/dev/null; then
  go env GOPATH 2>/dev/null
  if go list -m >/dev/null 2>&1; then go list -m all 2>/dev/null; fi
fi
EOF

  remote_exec <<'EOF' > "$report_dir/packages/rust.txt" || true
if command -v cargo >/dev/null; then cargo install --list 2>/dev/null; fi
EOF
}

collect_services() {
  log "Collecting services and startup data"
  remote_exec <<'EOF' > "$report_dir/services.txt" || true
if command -v systemctl >/dev/null; then
  systemctl list-units --type=service --all --no-pager
fi
if [ -d /etc/init.d ]; then
  ls -l /etc/init.d
fi
EOF
  remote_exec <<'EOF' > "$report_dir/cron.txt" || true
echo "# Per-user crontabs"
for user in $(cut -d: -f1 /etc/passwd); do
  crontab -l -u "$user" 2>/dev/null && echo "---"
done
echo
echo "# System cron directories"
for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
  if [ -d "$dir" ]; then
    echo "== $dir =="
    ls -al "$dir"
  fi
done
if [ -f /etc/anacrontab ]; then
  echo "--- /etc/anacrontab ---"
  cat /etc/anacrontab
fi
if [ -d /var/spool/cron ]; then
  echo "--- /var/spool/cron ---"
  ls -al /var/spool/cron
fi
EOF
}

collect_processes_ports() {
  log "Collecting processes and listening ports"
  remote_exec <<'EOF' > "$report_dir/processes.txt"
ps aux
EOF
  remote_exec <<'EOF' > "$report_dir/listening-ports.txt"
if command -v ss >/dev/null; then
  ss -tulpen
elif command -v netstat >/dev/null; then
  netstat -tulpen
else
  echo "Neither ss nor netstat available"
fi
EOF
}

collect_filesystems() {
  log "Collecting filesystem inventory"
  remote_exec <<'EOF' > "$report_dir/filesystems.txt"
df -hT
echo "---"
for dir in /opt /usr/local /srv /var/www /var/lib; do
  if [ -d "$dir" ]; then
    echo "== $dir =="
    ls -al "$dir"
  fi
done
EOF
}

collect_runtime_services() {
  log "Collecting runtime-specific service fingerprints"
  remote_exec <<'EOF' > "$report_dir/services-runtime.txt"
ps -eo pid,user,comm,args --no-headers | while read -r pid user comm args; do
  case "$comm" in
    php-fpm*|php|apache2|httpd|nginx|node|bun|python|python3|gunicorn|uwsgi|docker|dockerd|docker-compose|java|ruby|puma|passenger*|celery|redis-server|mongod|mysqld|postgres|postgresql|haproxy|supervisord)
      exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo n/a)"
      cwd="$(readlink -f "/proc/$pid/cwd" 2>/dev/null || echo n/a)"
      env_keys="$(if [ -r "/proc/$pid/environ" ]; then tr "\0" "\n" < "/proc/$pid/environ" | grep -E "^(PORT|HOST|DATABASE|REDIS|MQ|QUEUE|API|SERVICE|URL|ENV|CONFIG)_" | paste -sd ';' -; fi)"
      config_hint="$(for fd in /proc/$pid/fd/*; do [ -e "$fd" ] || continue; readlink -f "$fd" 2>/dev/null; done | grep -E "(\.conf$|\.ini$|\.yml$|\.yaml$|\.json$)" | sort -u | paste -sd ',' - 2>/dev/null || true)"
      printf 'PID=%s OWNER=%s COMM=%s\n' "$pid" "$user" "$comm"
      printf 'CMD=%s\n' "$args"
      printf 'EXEC=%s\n' "$exe"
      printf 'CWD=%s\n' "$cwd"
      printf 'ENV_HINTS=%s\n' "$env_keys"
      printf 'CONFIG_FDS=%s\n' "$config_hint"
      printf -- '---\n'
    ;;
  esac
done
EOF
}

collect_php_applications() {
  log "Collecting PHP application inventory"
  remote_exec <<'EOF' > "$report_dir/applications/php.txt" || true
echo "# PHP Runtime"
if command -v php >/dev/null; then
  php -v 2>/dev/null | head -n1
  echo
  echo "## php --ini"
  php --ini 2>/dev/null || true
fi
if pgrep -fa "php-fpm" >/dev/null 2>&1; then
  echo
  echo "## php-fpm pools"
  while IFS= read -r conf; do
    echo "== $conf =="
    cat "$conf"
  done < <(find /etc -maxdepth 6 -type f \( -name "php-fpm.conf" -o -path "*/pool.d/*.conf" -o -path "*/php-fpm.d/*.conf" \) -print 2>/dev/null)
fi
if command -v apache2ctl >/dev/null; then
  echo
  echo "## Apache PHP modules"
  apache2ctl -M 2>/dev/null | grep -i php || true
fi
echo
echo "## PHP project roots"
for root in /var/www /srv /opt /usr/local/share /home; do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 4 -type f \( -name "index.php" -o -name "composer.json" \) -printf '%h\n' 2>/dev/null
done | sort -u
EOF
}

collect_node_applications() {
  log "Collecting Node.js application inventory"
  remote_exec <<'EOF' > "$report_dir/applications/node.txt" || true
echo "# Node.js Runtime"
if command -v node >/dev/null; then
  echo "NODE_VERSION=$(node -v 2>/dev/null)"
fi
if command -v bun >/dev/null; then
  echo "BUN_VERSION=$(bun -v 2>/dev/null)"
fi
if command -v npm >/dev/null; then
  echo "NPM_VERSION=$(npm -v 2>/dev/null)"
fi
if command -v yarn >/dev/null; then
  echo "YARN_VERSION=$(yarn -v 2>/dev/null)"
fi
echo
echo "## Node/Bun processes"
ps -eo pid,user,args --no-headers | grep -E "(node|bun)" | grep -v grep || true
echo
echo "## PM2 applications"
if command -v pm2 >/dev/null; then
  pm2 list 2>/dev/null || true
  pm2 jlist 2>/dev/null || true
fi
echo
echo "## Node project manifests"
for root in /var/www /srv /opt /usr/local/share /home; do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 5 -type f \( -name "package.json" -o -name "bun.lockb" -o -name "pnpm-lock.yaml" -o -name "yarn.lock" \) -print 2>/dev/null
done
EOF
}

collect_python_applications() {
  log "Collecting Python application inventory"
  remote_exec <<'EOF' > "$report_dir/applications/python.txt" || true
echo "# Python Runtime"
if command -v python >/dev/null; then
  python --version 2>&1
fi
if command -v python3 >/dev/null; then
  python3 --version 2>&1
fi
if command -v pipenv >/dev/null; then
  echo "PIPENV_VERSION=$(pipenv --version 2>/dev/null)"
fi
if command -v poetry >/dev/null; then
  echo "POETRY_VERSION=$(poetry --version 2>/dev/null)"
fi
echo
echo "## Python application processes"
ps -eo pid,user,args --no-headers | grep -E "(python|gunicorn|uwsgi|celery)" | grep -v grep || true
echo
echo "## Virtual environments"
search_dirs="/var/www /srv /opt /usr/local/share /home"
for dir in $search_dirs; do
  [ -d "$dir" ] || continue
  find "$dir" -maxdepth 5 -type f -name "pyvenv.cfg" -print 2>/dev/null
done
echo
echo "## Django/Flask project hints"
for root in /var/www /srv /opt /usr/local/share /home; do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 5 -type f \( -name "manage.py" -o -name "wsgi.py" -o -name "asgi.py" -o -name "app.py" \) -print 2>/dev/null
done
EOF
}

collect_container_applications() {
  log "Collecting container workload inventory"
  remote_exec <<'EOF' > "$report_dir/applications/containers.txt" || true
echo "# Docker"
if command -v docker >/dev/null; then
  docker info 2>/dev/null || true
  docker ps -a 2>/dev/null || true
  docker image ls 2>/dev/null || true
  while IFS= read -r compose; do
    echo "Compose file: $compose"
  done < <(find /var/www /srv /opt /usr/local/share /etc -maxdepth 5 -type f \( -name "docker-compose.yml" -o -name "compose.yml" -o -name "compose.yaml" \) -print 2>/dev/null)
fi
echo
echo "# Podman"
if command -v podman >/dev/null; then
  podman info 2>/dev/null || true
  podman ps -a 2>/dev/null || true
  podman image ls 2>/dev/null || true
fi
echo
echo "# Kubernetes kubelet"
if command -v systemctl >/dev/null; then
  if systemctl list-units --type=service --all 2>/dev/null | grep -q kubelet; then
    systemctl status kubelet 2>/dev/null || true
  fi
fi
EOF
}

collect_application_modules() {
  collect_php_applications
  collect_node_applications
  collect_python_applications
  collect_container_applications
}

collect_databases() {
  log "Collecting database service inventory"
  remote_exec <<'EOF' > "$report_dir/databases/summary.txt" || true
echo "# Database processes"
ps -eo pid,user,comm,args --no-headers | grep -E "(mysqld|mariadbd|mysql|postgres|postgresql|mongod|redis-server|memcached|etcd)" | grep -v grep || true

echo
echo "## MySQL / MariaDB"
if command -v mysql >/dev/null; then
  mysql --version 2>/dev/null || true
fi
if command -v my_print_defaults >/dev/null; then
  my_print_defaults mysqld 2>/dev/null | grep -E '^--(datadir|socket|port)'
fi
if [ -d /etc/mysql ]; then
  echo "-- Config files --"
  find /etc/mysql -maxdepth 3 -type f -name "*.cnf" -print 2>/dev/null
fi

echo
echo "## PostgreSQL"
if command -v psql >/dev/null; then
  psql --version 2>/dev/null || true
fi
while IFS= read -r conf; do
  echo "Config: $conf"
  grep -E '^(data_directory|port)' "$conf" 2>/dev/null || true
done < <(find /etc /var/lib/postgresql -maxdepth 5 -type f -name "postgresql.conf" 2>/dev/null)
while IFS= read -r hba; do
  echo "Access control: $hba"
done < <(find /etc /var/lib/postgresql -maxdepth 5 -type f -name "pg_hba.conf" 2>/dev/null)

echo
echo "## MongoDB"
if command -v mongod >/dev/null; then
  mongod --version 2>/dev/null || true
fi
while IFS= read -r conf; do
  echo "Config: $conf"
  grep -E '^(storage\.|systemLog\.|net\.)' "$conf" 2>/dev/null || true
done < <(find /etc -maxdepth 4 -type f -name "mongod.conf" 2>/dev/null)

echo
echo "## Redis"
if command -v redis-server >/dev/null; then
  redis-server --version 2>/dev/null || true
fi
while IFS= read -r conf; do
  echo "Config: $conf"
  grep -E '^(dir|bind|port|requirepass)' "$conf" 2>/dev/null || true
done < <(find /etc -maxdepth 4 -type f \( -name "redis.conf" -o -path "*/redis/*.conf" \) 2>/dev/null)

echo
echo "## Other data stores"
while IFS= read -r conf; do
  echo "Elasticsearch config: $conf"
done < <(find /etc -maxdepth 4 -type f -name "elasticsearch.yml" 2>/dev/null)
while IFS= read -r conf; do
  echo "RabbitMQ config: $conf"
done < <(find /etc -maxdepth 4 -type f \( -name "rabbitmq.conf" -o -name "advanced.config" \) 2>/dev/null)
EOF
}

collect_networking() {
  log "Collecting networking configuration"
  remote_exec <<'EOF' > "$report_dir/network/networking.txt" || true
echo "# Hostname & identity"
hostname 2>/dev/null || true
hostnamectl 2>/dev/null || true

echo
echo "# Interfaces"
ip -brief addr show 2>/dev/null || ip addr show 2>/dev/null || true

echo
echo "# Routes"
ip route show 2>/dev/null || true
ip rule show 2>/dev/null || true

echo
echo "# DNS"
cat /etc/resolv.conf 2>/dev/null || true

echo
echo "# Hosts file"
cat /etc/hosts 2>/dev/null || true

echo
echo "# Firewall"
if command -v nft >/dev/null; then
  nft list ruleset 2>/dev/null || true
fi
if command -v iptables >/dev/null; then
  iptables -S 2>/dev/null || true
  iptables -L -n 2>/dev/null || true
fi
if command -v firewall-cmd >/dev/null; then
  firewall-cmd --list-all 2>/dev/null || true
fi
if command -v ufw >/dev/null; then
  ufw status verbose 2>/dev/null || true
fi

echo
echo "# Active listeners"
if command -v ss >/dev/null; then
  ss -tulpn 2>/dev/null || true
elif command -v netstat >/dev/null; then
  netstat -tulpn 2>/dev/null || true
fi
EOF
}

collect_manifests() {
  log "Collecting dependency manifests"
  local manifest_list="$report_dir/manifests/manifest-paths.txt"
  remote_exec <<'EOF' > "$manifest_list"
search_dirs="/var/www /srv /opt /usr/local /home"
for dir in $search_dirs; do
  [ -d "$dir" ] || continue
  find "$dir" -maxdepth 6 -type f \(
    -name "composer.json" -o
    -name "composer.lock" -o
    -name "package.json" -o
    -name "package-lock.json" -o
    -name "bun.lockb" -o
    -name "requirements.txt" -o
    -name "Pipfile" -o
    -name "poetry.lock" -o
    -name "pyproject.toml" -o
    -name "environment.yml" -o
    -name "Gemfile" -o
    -name "Gemfile.lock"
  ) 2>/dev/null
done
EOF
  while IFS= read -r remote_path; do
    [[ -z "$remote_path" ]] && continue
    local rel_path="${remote_path#/}"
    local dest="$report_dir/manifests/$rel_path"
    mkdir -p "$(dirname "$dest")"
    if ! "${scp_cmd[@]}" "$target:$remote_path" "$dest" 2>/dev/null; then
      log "Warning: failed to copy manifest $remote_path"
    fi
  done < "$manifest_list"
}

collect_configs() {
  log "Collecting configuration files for services"
  local config_list="$report_dir/configs/config-paths.txt"
  remote_exec <<'EOF' > "$config_list"
candidates="/etc /opt /var/www /srv /usr/local"
for dir in $candidates; do
  [ -d "$dir" ] || continue
  find "$dir" -maxdepth 4 -type f \(
    -name "*.env" -o
    -name "*.ini" -o
    -name "*.yaml" -o
    -name "*.yml" -o
    -name "*.json" -o
    -name "docker-compose.yml" -o
    -name "*.conf"
  ) 2>/dev/null
done
EOF
  while IFS= read -r remote_path; do
    [[ -z "$remote_path" ]] && continue
    local rel_path="${remote_path#/}"
    local dest="$report_dir/configs/$rel_path"
    mkdir -p "$(dirname "$dest")"
    if ! "${scp_cmd[@]}" "$target:$remote_path" "$dest" 2>/dev/null; then
      log "Warning: failed to copy config $remote_path"
    fi
  done < "$config_list"
}

csv_escape() {
  local input="$1"
  local dq='"'
  input=${input//$dq/$dq$dq}
  printf '"%s"' "$input"
}

document_external_dependencies() {
  log "Documenting external dependencies"
  local raw_file="$report_dir/external-dependencies-raw.txt"
  local search_script
  search_script=$(cat <<'EOF'
search_dirs="/etc /opt /var/www /srv /usr/local"
for dir in $search_dirs; do
  [ -d "$dir" ] || continue
  grep -R -nE "(postgres|pgsql|mysql|mariadb|mongodb|redis|rabbitmq|amqp|kafka|sqs|sns|smtp|ldap|api_key|api-url|://)" "$dir" 2>/dev/null
done
EOF
)
  remote_exec "$search_script" > "$raw_file"
  local csv_file="$report_dir/external-dependencies.csv"
  echo 'service_type,endpoint,file,line,matched_text' > "$csv_file"
  while IFS=: read -r file line content; do
    [[ -z "$file" ]] && continue
    local service="unknown"
    case "$content" in
      *postgres*|*pgsql*) service="postgresql" ;;
      *mysql*|*mariadb*) service="mysql" ;;
      *mongodb*) service="mongodb" ;;
      *redis*) service="redis" ;;
      *rabbitmq*|*amqp*) service="rabbitmq" ;;
      *kafka*) service="kafka" ;;
      *sqs*) service="aws-sqs" ;;
      *sns*) service="aws-sns" ;;
      *smtp*) service="smtp" ;;
      *ldap*) service="ldap" ;;
      *api_key*|*api-key*|*api-url*|*https://*|*http://*) service="api" ;;
    esac
    local endpoint
    endpoint="$(grep -oE '([A-Za-z0-9_.-]+://[^ "'"'"']+|[A-Za-z0-9_.-]+:[0-9]{2,5})' <<<"$content" | head -n1)"
    printf '%s,%s,%s,%s,%s\n' \
      "$(csv_escape "$service")" \
      "$(csv_escape "${endpoint:-}")" \
      "$(csv_escape "$file")" \
      "$(csv_escape "${line:-}")" \
      "$(csv_escape "$content")" >> "$csv_file"
  done < "$raw_file"
}

assemble_migration_plan() {
  log "Assembling migration plan"
  local plan="$report_dir/migration-plan.md"
  cat > "$plan" <<'PLAN'
# Migration Plan

## Overview
- Host inventoried: TARGET_PLACEHOLDER
- Inventory timestamp (UTC): TIMESTAMP_PLACEHOLDER

## System Summary
See [system-info.txt](./system-info.txt).

## Packages
- System packages: [packages/system.txt](./packages/system.txt)
- Python packages: [packages/python.txt](./packages/python.txt)
- Node/Bun packages: [packages/node.txt](./packages/node.txt)
- Ruby gems: [packages/ruby.txt](./packages/ruby.txt)
- Other tooling: [packages/pipx.txt](./packages/pipx.txt), [packages/go.txt](./packages/go.txt), [packages/rust.txt](./packages/rust.txt)

## Services and Processes
- systemd/SysV inventory: [services.txt](./services.txt)
- Cron jobs: [cron.txt](./cron.txt)
- Runtime fingerprints: [services-runtime.txt](./services-runtime.txt)
- Active processes: [processes.txt](./processes.txt)
- Listening ports: [listening-ports.txt](./listening-ports.txt)

## Application Modules
- PHP details: [applications/php.txt](./applications/php.txt)
- Node/Bun details: [applications/node.txt](./applications/node.txt)
- Python details: [applications/python.txt](./applications/python.txt)
- Containers: [applications/containers.txt](./applications/containers.txt)
- Dependency manifests: contents of [manifests/](./manifests)
- Configuration files staged in [configs/](./configs)
- External dependency findings: [external-dependencies.csv](./external-dependencies.csv)

## Database Inventory
- Database services and configs: [databases/summary.txt](./databases/summary.txt)

## Networking
- Network configuration and firewall: [network/networking.txt](./network/networking.txt)

## Storage
- Filesystem overview: [filesystems.txt](./filesystems.txt)

## Next Steps
1. Review runtime fingerprints to identify hosted applications and their launch commands.
2. Export relevant databases or stateful services referenced in `external-dependencies.csv`.
3. Recreate system and language packages on the destination host.
4. Copy application code and configuration files from `manifests/` and `configs/`.
5. Validate secrets and rotate credentials as appropriate.
6. Test the application in a staging environment before final cutover.
PLAN
  sed -i "s/TARGET_PLACEHOLDER/$target/" "$plan"
  sed -i "s/TIMESTAMP_PLACEHOLDER/$timestamp/" "$plan"
}

collect_system_info
collect_users_groups
collect_packages
collect_services
collect_processes_ports
collect_filesystems
collect_runtime_services
collect_application_modules
collect_databases
collect_networking
collect_manifests
collect_configs
document_external_dependencies
assemble_migration_plan

log "Inventory completed: $report_dir"
