#!/usr/bin/env python3

import argparse
import json
import os
import sys
import subprocess
import datetime
import concurrent.futures
import getpass
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

from modules.system_info import SystemInfoModule
from modules.network import NetworkModule
from modules.applications import ApplicationsModule
from modules.services import ServicesModule
from modules.containers import ContainersModule
from modules.databases import DatabasesModule
from modules.security import SecurityModule
from modules.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class ServerDiscovery:
    def __init__(self, target: Optional[str] = None, ssh_options: List[str] = None,
                 local: bool = False, output_dir: str = "reports", password: Optional[str] = None,
                 use_password: bool = False, key_passphrase: Optional[str] = None):
        self.target = target
        self.ssh_options = ssh_options or []
        self.local = local
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = self.output_dir / self.timestamp
        self.results = {}
        self.password = password
        self.use_password = use_password
        self.key_passphrase = key_passphrase
        self.ssh_env = None
        self.askpass_script = None
        self.ssh_control_path = None
        self.ssh_master_started = False

        # Setup SSH authentication and multiplexing
        if not self.local:
            if self.use_password:
                self._setup_ssh_password_auth()
            elif self.key_passphrase is not None:
                self._setup_ssh_key_passphrase()

            # Setup SSH connection multiplexing for performance
            self._setup_ssh_multiplexing()
        
        self.modules = {
            'system': SystemInfoModule(self),
            'network': NetworkModule(self),
            'applications': ApplicationsModule(self),
            'services': ServicesModule(self),
            'containers': ContainersModule(self),
            'databases': DatabasesModule(self),
            'security': SecurityModule(self)
        }
        
        self._create_output_directory()
    
    def _setup_ssh_password_auth(self):
        """Setup SSH password authentication using sshpass"""
        # Check if sshpass is available
        try:
            subprocess.run(['which', 'sshpass'], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            logger.warning("sshpass not found. Install it for password authentication: brew install sshpass (macOS) or apt-get install sshpass (Ubuntu)")
            logger.info("Falling back to interactive SSH (you'll be prompted for password)")
            return

        if not self.password:
            self.password = getpass.getpass(f"Enter SSH password for {self.target}: ")

        # Set up environment for sshpass
        self.ssh_env = os.environ.copy()
        self.ssh_env['SSHPASS'] = self.password

    def _setup_ssh_key_passphrase(self):
        """Setup SSH key passphrase using SSH_ASKPASS"""
        # Create a temporary askpass script
        fd, self.askpass_script = tempfile.mkstemp(suffix='.sh', text=True)

        try:
            with os.fdopen(fd, 'w') as f:
                f.write('#!/bin/sh\n')
                f.write(f'echo "{self.key_passphrase}"\n')

            # Make it executable
            os.chmod(self.askpass_script, 0o700)

            # Set up environment for SSH_ASKPASS
            self.ssh_env = os.environ.copy()
            self.ssh_env['SSH_ASKPASS'] = self.askpass_script
            self.ssh_env['DISPLAY'] = ':0'  # Required for SSH_ASKPASS to work
            self.ssh_env['SSH_ASKPASS_REQUIRE'] = 'force'  # Force askpass even in terminal

            logger.info("SSH key passphrase configured")
        except Exception as e:
            logger.error(f"Failed to setup SSH key passphrase: {e}")
            if self.askpass_script and os.path.exists(self.askpass_script):
                os.unlink(self.askpass_script)
            raise

    def _setup_ssh_multiplexing(self):
        """Setup SSH connection multiplexing for better performance"""
        # Create a control socket file
        fd, self.ssh_control_path = tempfile.mkstemp(suffix='.sock', prefix='ssh_mux_')
        os.close(fd)
        os.unlink(self.ssh_control_path)  # SSH will create it

        # Add multiplexing options to SSH options
        multiplex_options = [
            '-o', 'ControlMaster=auto',
            '-o', f'ControlPath={self.ssh_control_path}',
            '-o', 'ControlPersist=60s'
        ]
        self.ssh_options.extend(multiplex_options)

        logger.info("SSH connection multiplexing enabled for improved performance")

    def __del__(self):
        """Cleanup temporary files and SSH connections"""
        # Clean up askpass script
        if self.askpass_script and os.path.exists(self.askpass_script):
            try:
                os.unlink(self.askpass_script)
            except:
                pass

        # Clean up SSH control socket
        if self.ssh_control_path:
            try:
                # Stop the master connection
                if not self.local:
                    subprocess.run(
                        ['ssh', '-O', 'exit', '-o', f'ControlPath={self.ssh_control_path}', self.target],
                        capture_output=True,
                        timeout=2
                    )
            except:
                pass

            # Remove control socket file
            if os.path.exists(self.ssh_control_path):
                try:
                    os.unlink(self.ssh_control_path)
                except:
                    pass

    def _create_output_directory(self):
        self.report_dir.mkdir(parents=True, exist_ok=True)
        for subdir in ['raw', 'configs', 'manifests']:
            (self.report_dir / subdir).mkdir(exist_ok=True)
    
    def execute_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """Execute command either locally or via SSH"""
        try:
            if self.local:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            else:
                ssh_cmd = self._build_ssh_command(command)
                logger.debug(f"Executing SSH command: {' '.join(ssh_cmd)}")
                result = subprocess.run(
                    ssh_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=self.ssh_env
                )
                
                if result.returncode != 0:
                    logger.debug(f"Command failed: {command}")
                    logger.debug(f"SSH stderr: {result.stderr}")
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'stdout': '',
                'stderr': f'Command timed out after {timeout} seconds',
                'returncode': -1
            }
        except Exception as e:
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'returncode': -1
            }
    
    def execute_commands_parallel(self, commands: Dict[str, str], timeout: int = 30) -> Dict[str, Dict]:
        """Execute multiple commands in parallel"""
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self.execute_command, cmd, timeout): name 
                for name, cmd in commands.items()
            }
            
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as e:
                    results[name] = {
                        'success': False,
                        'stdout': '',
                        'stderr': str(e),
                        'returncode': -1
                    }
        
        return results
    
    def _build_ssh_command(self, command: str) -> List[str]:
        """Build SSH command with appropriate authentication method"""
        if self.use_password and self.ssh_env and 'SSHPASS' in self.ssh_env:
            # Use sshpass for password authentication
            ssh_cmd = ['sshpass', '-e', 'ssh']
        else:
            # Use standard SSH (key-based or interactive)
            ssh_cmd = ['ssh']
        
        # Add common SSH options for non-interactive use
        base_options = [
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR'
        ]
        
        return ssh_cmd + base_options + self.ssh_options + [self.target, command]
    
    def _build_scp_command(self, remote_path: str, local_path: str) -> List[str]:
        """Build SCP command with appropriate authentication method"""
        if self.use_password and self.ssh_env and 'SSHPASS' in self.ssh_env:
            # Use sshpass for password authentication
            scp_cmd = ['sshpass', '-e', 'scp']
        else:
            # Use standard SCP (key-based or interactive)
            scp_cmd = ['scp']
        
        # Add common SCP options
        base_options = [
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR'
        ]
        
        return scp_cmd + base_options + self.ssh_options + [f"{self.target}:{remote_path}", local_path]
    
    def copy_file(self, remote_path: str, local_path: Path) -> bool:
        """Copy file from remote to local"""
        if self.local:
            try:
                import shutil
                shutil.copy2(remote_path, local_path)
                return True
            except Exception as e:
                logger.warning(f"Failed to copy {remote_path}: {e}")
                return False
        else:
            scp_cmd = self._build_scp_command(remote_path, str(local_path))
            result = subprocess.run(scp_cmd, capture_output=True, text=True, env=self.ssh_env)
            return result.returncode == 0
    
    def discover(self, modules: Optional[List[str]] = None):
        """Run discovery process"""
        logger.info(f"Starting discovery on {self.target if not self.local else 'local system'}")
        
        if modules:
            selected_modules = {k: v for k, v in self.modules.items() if k in modules}
        else:
            selected_modules = self.modules
        
        for name, module in selected_modules.items():
            logger.info(f"Running {name} module...")
            try:
                self.results[name] = module.collect()
            except Exception as e:
                logger.error(f"Module {name} failed: {e}")
                self.results[name] = {'error': str(e)}
        
        logger.info("Discovery completed")
    
    def save_results(self, format: str = 'json'):
        """Save results in specified format"""
        if format == 'json' or format == 'all':
            output_file = self.report_dir / 'discovery.json'
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            logger.info(f"JSON report saved to {output_file}")
        
        if format == 'html' or format == 'all':
            generator = ReportGenerator(self.results, self.report_dir)
            html_file = generator.generate_html()
            logger.info(f"HTML report saved to {html_file}")
        
        if format == 'csv' or format == 'all':
            generator = ReportGenerator(self.results, self.report_dir)
            csv_files = generator.generate_csv()
            logger.info(f"CSV files saved to {self.report_dir}")
    
    def print_summary(self):
        """Print discovery summary"""
        print("\n" + "="*50)
        print("DISCOVERY SUMMARY")
        print("="*50)
        
        if 'system' in self.results:
            sys_info = self.results['system']
            print(f"Hostname: {sys_info.get('hostname', 'Unknown')}")
            print(f"OS: {sys_info.get('os_name', 'Unknown')} {sys_info.get('os_version', '')}")
            print(f"Kernel: {sys_info.get('kernel', 'Unknown')}")
            print(f"Architecture: {sys_info.get('architecture', 'Unknown')}")
            print(f"CPUs: {sys_info.get('cpu_count', 'Unknown')}")
            print(f"Memory: {sys_info.get('memory_total', 'Unknown')}")
        
        if 'applications' in self.results:
            apps = self.results['applications']
            print(f"\nDetected Applications:")
            for category, items in apps.items():
                if items:
                    print(f"  - {category}: {len(items)} found")
        
        if 'services' in self.results:
            services = self.results['services']
            if 'systemd' in services:
                active_services = [s for s in services['systemd'] if 'active' in s.get('state', '')]
                print(f"\nActive Services: {len(active_services)}")
        
        if 'containers' in self.results:
            containers = self.results['containers']
            if 'docker' in containers and containers['docker'].get('containers'):
                print(f"Docker Containers: {len(containers['docker']['containers'])}")
        
        print(f"\nReport Directory: {self.report_dir}")
        print("="*50)


def main():
    parser = argparse.ArgumentParser(description='Server Discovery Tool - Comprehensive VPS/Server Analysis')
    parser.add_argument('target', nargs='?', help='SSH target (user@host) for remote discovery')
    parser.add_argument('--local', action='store_true', help='Run discovery on local system')
    parser.add_argument('--ssh-options', nargs='*', default=[], help='Additional SSH options (e.g., --ssh-options -- -i ./key -p 2222)')
    parser.add_argument('--key', '-i', help='Path to SSH private key file')
    parser.add_argument('--password', action='store_true', help='Use password authentication (will prompt securely)')
    parser.add_argument('--ssh-password', help='SSH password (not recommended, use --password for secure prompt)')
    parser.add_argument('--key-passphrase', help='SSH key passphrase for encrypted keys')
    parser.add_argument('--modules', nargs='*', choices=['system', 'network', 'applications', 
                                                          'services', 'containers', 'databases', 'security'],
                       help='Specific modules to run (default: all)')
    parser.add_argument('--output', choices=['json', 'html', 'csv', 'all'], default='all',
                       help='Output format (default: all)')
    parser.add_argument('--output-dir', default='reports', help='Output directory (default: reports)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if not args.local and not args.target:
        parser.error("Either specify a target (user@host) or use --local flag")
    
    if args.local and args.target:
        parser.error("Cannot use both --local and target")
    
    # Handle password authentication
    use_password = args.password or args.ssh_password
    password = args.ssh_password if args.ssh_password else None

    if args.ssh_password:
        logger.warning("Warning: Providing password via command line is not secure. Use --password flag for secure prompt.")

    # Handle SSH key
    ssh_options = args.ssh_options.copy() if args.ssh_options else []
    if args.key:
        ssh_options.extend(['-i', args.key])

    # Handle key passphrase
    key_passphrase = args.key_passphrase if hasattr(args, 'key_passphrase') else None

    discovery = ServerDiscovery(
        target=args.target,
        ssh_options=ssh_options,
        local=args.local,
        output_dir=args.output_dir,
        password=password,
        use_password=use_password,
        key_passphrase=key_passphrase
    )
    
    try:
        discovery.discover(modules=args.modules)
        discovery.save_results(format=args.output)
        discovery.print_summary()
    except KeyboardInterrupt:
        logger.info("Discovery interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Discovery failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()