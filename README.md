# The Red Pill - VPS/Server Discovery Tool

A comprehensive Python-based tool for discovering and analyzing Linux servers, providing detailed insights into system configuration, applications, services, security posture, and infrastructure components.

## 🎯 Features

### Base Infrastructure Discovery
- **System Information**: OS version, kernel, hardware specs, virtualization
- **Network Configuration**: Interfaces, routing, DNS, firewall rules
- **Security Analysis**: SSH config, SSL certificates, open ports, security updates
- **Storage**: Disk usage, filesystem analysis, mount points

### Application & Service Detection
- **Runtime Environments**: PHP, Node.js, Python, Ruby, Java, .NET, Go, Rust
- **Web Frameworks**: Laravel, Symfony, React, Vue, Angular, Django, Flask, Rails
- **Content Management**: WordPress, Drupal, Joomla, Magento, Moodle
- **Process Managers**: PM2, Supervisor, systemd services, cron jobs

### Container & Orchestration
- **Docker**: Containers, images, volumes, networks, compose projects
- **Kubernetes**: Clusters, pods, services, deployments
- **Alternative Runtimes**: Podman, containerd, CRI-O

### Database Services
- **SQL Databases**: MySQL, PostgreSQL, SQLite
- **NoSQL**: MongoDB, Redis, Elasticsearch, CouchDB
- **Cache Systems**: Memcached, Redis
- **Enterprise**: Cassandra, specialized databases

### Security & Compliance
- **Access Control**: SSH configuration, sudo rules, user accounts
- **Firewall Analysis**: iptables, UFW, firewalld, nftables
- **SSL/TLS**: Certificate discovery and validation
- **Security Frameworks**: SELinux, AppArmor, Fail2ban

## 🚀 Quick Start

### Prerequisites
- Python 3.9+ 
- [uv](https://github.com/astral-sh/uv) package manager
- SSH access to target servers (for remote discovery)
- Appropriate permissions on target systems

### Installation

**Using uv (Recommended):**
```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and setup
git clone <repository-url>
cd the-red-pill

# Install dependencies
uv sync
```

**For Development:**
```bash
# Install with development dependencies
uv sync --extra dev --extra test --extra docs

# Set up pre-commit hooks
make setup-dev
```

### Basic Usage

**Local System Discovery:**
```bash
uv run python server_discovery.py --local
# Or using make
make run
```

**Remote System Discovery:**
```bash
# Using SSH keys (default)
uv run python server_discovery.py user@hostname
# Or using make
make run-remote TARGET=user@hostname

# Using password authentication
uv run python server_discovery.py user@hostname --password
```

**With SSH Options:**
```bash
# Custom SSH key and port
uv run python server_discovery.py user@hostname --ssh-options "-i /path/to/key" "-p 2222"

# Password auth with custom port
uv run python server_discovery.py user@hostname --password --ssh-options "-p 2222"
```

**Specific Modules Only:**
```bash
uv run python server_discovery.py user@hostname --modules system network applications
```

**Custom Output:**
```bash
uv run python server_discovery.py user@hostname --output html --output-dir ./my-reports
```

## 📋 Command Line Options

```
usage: server_discovery.py [-h] [--local] [--ssh-options SSH_OPTIONS] [--password]
                          [--ssh-password SSH_PASSWORD]
                          [--modules {system,network,applications,services,containers,databases,security}]
                          [--output {json,html,csv,all}] [--output-dir OUTPUT_DIR]
                          [--verbose] [target]

positional arguments:
  target                SSH target (user@host) for remote discovery

optional arguments:
  -h, --help            show this help message and exit
  --local               Run discovery on local system
  --ssh-options SSH_OPTIONS
                        Additional SSH options
  --password            Use password authentication (will prompt securely)
  --ssh-password SSH_PASSWORD
                        SSH password (not recommended, use --password for secure prompt)
  --modules MODULES     Specific modules to run (default: all)
  --output OUTPUT       Output format (default: all)
  --output-dir OUTPUT_DIR
                        Output directory (default: reports)
  --verbose             Enable verbose logging
```

## 📊 Output Formats

### JSON Report
- Structured data in JSON format
- Machine-readable for automation
- Complete discovery results

### HTML Report
- Interactive web-based report
- Collapsible sections and tables
- Mobile-responsive design
- Summary dashboard with key metrics

### CSV Exports
- Separate CSV files for different data types
- Import into spreadsheets or databases
- Useful for inventory management

## 🏗️ Architecture

### Modular Design
The tool is built with a modular architecture for easy extension:

```
server_discovery.py          # Main orchestrator
modules/
├── system_info.py          # OS and hardware detection
├── network.py              # Network and firewall analysis
├── applications.py         # Application runtime detection
├── services.py             # Service and process discovery
├── containers.py           # Container platform analysis
├── databases.py            # Database service detection
├── security.py             # Security configuration analysis
└── report_generator.py     # Multi-format report generation
```

### Discovery Process
1. **Parallel Execution**: Commands run concurrently for speed
2. **Non-Invasive**: Read-only operations, no system changes
3. **Error Handling**: Graceful failure with partial results
4. **Timeout Protection**: Commands have timeout limits

## 🛠️ Development Workflow

### Using Make Commands
The project includes a Makefile for common development tasks:

```bash
# Install development dependencies
make install-dev

# Run tests
make test
make test-cov  # with coverage

# Code formatting and linting
make format    # format code with black/isort
make lint      # run ruff and mypy
make check     # run lint + test

# Clean up
make clean     # remove build artifacts

# Build documentation
make docs
make docs-serve  # serve locally

# Run examples
make run              # local discovery
make example-local    # local with HTML output
make run-remote TARGET=user@host  # remote discovery
```

### Adding Dependencies

**Runtime Dependencies:**
```bash
# Add a new runtime dependency
uv add package-name

# Add with version constraint
uv add "package-name>=1.0.0"
```

**Development Dependencies:**
```bash
# Add development dependency
uv add --group dev package-name

# Add test dependency  
uv add --group test package-name
```

### Project Scripts
The tool can be run directly via uv:
```bash
# Main discovery script
uv run server-discovery --local
uv run discover --local  # alias

# Or via python module
uv run python server_discovery.py --local
```

## 🔧 Advanced Usage

### SSH Authentication

**Key-based Authentication (Recommended):**
```bash
# Set up SSH keys for passwordless access
ssh-keygen -t ed25519 -C "your_email@example.com"
ssh-copy-id user@hostname

# Run discovery with key-based auth
uv run python server_discovery.py user@hostname
```

**Password Authentication:**
```bash
# Install sshpass for non-interactive password auth (optional but recommended)
# macOS: brew install sshpass
# Ubuntu: apt-get install sshpass

# Secure password prompt (recommended)
uv run python server_discovery.py user@hostname --password

# Or with make command
make run-remote-password TARGET=user@hostname
make run-remote TARGET=user@hostname PASSWORD=true
```

**Advanced SSH Options:**
```bash
# Custom port and identity file
uv run python server_discovery.py user@hostname --ssh-options "-p 2222" "-i ~/.ssh/custom_key"

# Password auth with custom port
uv run python server_discovery.py user@hostname --password --ssh-options "-p 2222"

# Disable host key checking (for dynamic environments)
uv run python server_discovery.py user@hostname --ssh-options "-o StrictHostKeyChecking=no"
```

### Multiple Servers
Run discovery across multiple servers:
```bash
for server in server1 server2 server3; do
    uv run python server_discovery.py user@$server --output-dir reports/$server
done
```

### Automated Reporting
Schedule regular discovery runs:
```bash
# Add to crontab for weekly discovery
0 2 * * 0 cd /path/to/the-red-pill && uv run python server_discovery.py user@server --output-dir /var/reports/$(date +\%Y-\%m-\%d)
```

## 📈 Use Cases

### Migration Planning
- **Infrastructure Audit**: Complete inventory of current setup
- **Dependency Mapping**: Identify application interdependencies  
- **Resource Planning**: Understand hardware and software requirements
- **Risk Assessment**: Security and compliance review

### Security Auditing
- **Attack Surface Analysis**: Open ports and exposed services
- **Configuration Review**: Security settings and best practices
- **Compliance Checking**: Security framework status
- **Vulnerability Assessment**: Outdated software identification

### DevOps & Monitoring
- **Environment Documentation**: Automated infrastructure documentation
- **Change Detection**: Compare discoveries over time
- **Capacity Planning**: Resource utilization analysis
- **Troubleshooting**: Comprehensive system state capture

### Cloud Migration
- **Pre-migration Assessment**: Current state documentation
- **Service Inventory**: Applications and dependencies
- **Security Posture**: Current security configuration
- **Resource Mapping**: Hardware and software requirements

## 🛡️ Security Considerations

### Permissions Required
- **Read Access**: Configuration files, process lists, network status
- **No Modifications**: Tool performs only read operations
- **SSH Access**: Secure remote access via SSH keys preferred
- **Privilege Escalation**: Some commands may require sudo for complete information

### Data Sensitivity
- **Configuration Files**: May contain sensitive information
- **Network Information**: Topology and security details
- **Process Information**: Running services and applications
- **Secure Storage**: Store reports in secure locations

## 🤝 Contributing

### Adding New Modules
1. Create new module in `modules/` directory
2. Implement discovery class with `collect()` method
3. Add module to main orchestrator
4. Update documentation

### Extending Existing Modules
- Add new command detection logic
- Implement additional parsing methods
- Update report generation for new data

### Testing
- Test on various Linux distributions
- Verify with different privilege levels
- Test error handling and edge cases

## 📝 Changelog

### v1.0.0 - Initial Release
- Complete modular architecture
- Seven discovery modules
- Multiple output formats
- HTML report generation
- Security-focused analysis
- Container platform support
- Database service detection

## 📜 License

[Specify your license here]

## 🆘 Support

For issues, feature requests, or questions:
- Create GitHub issues for bugs and features
- Provide system information and error logs
- Include command line arguments used

## 🙏 Acknowledgments

Built for comprehensive infrastructure analysis and migration planning.
Designed for security professionals, system administrators, and DevOps teams.

