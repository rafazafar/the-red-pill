import re
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class SecurityModule:
    def __init__(self, discovery):
        self.discovery = discovery
    
    def collect(self) -> Dict[str, Any]:
        """Collect security-related information"""
        logger.info("Collecting security information...")
        
        security = {
            'ssl_certificates': self._collect_ssl_certificates(),
            'ssh_config': self._collect_ssh_configuration(),
            'fail2ban': self._collect_fail2ban_info(),
            'apparmor': self._collect_apparmor_info(),
            'selinux': self._collect_selinux_info(),
            'sudo_config': self._collect_sudo_configuration(),
            'iptables_summary': self._collect_iptables_summary(),
            'open_ports': self._collect_open_ports(),
            'security_updates': self._check_security_updates()
        }
        
        return security
    
    def _collect_ssl_certificates(self) -> List[Dict]:
        """Find and analyze SSL certificates"""
        certificates = []
        
        # Common SSL certificate locations
        cert_locations = [
            '/etc/ssl/certs/',
            '/etc/letsencrypt/live/',
            '/etc/nginx/ssl/',
            '/etc/apache2/ssl/',
            '/etc/httpd/ssl/',
            '/usr/local/etc/ssl/'
        ]
        
        for location in cert_locations:
            find_cmd = f'find {location} -name "*.crt" -o -name "*.pem" -o -name "*.cert" 2>/dev/null | head -20'
            result = self.discovery.execute_command(find_cmd, timeout=10)
            
            if result.get('success'):
                for cert_path in result['stdout'].splitlines():
                    if cert_path:
                        # Get certificate info
                        cert_cmd = f'openssl x509 -in {cert_path} -noout -subject -dates 2>/dev/null'
                        cert_result = self.discovery.execute_command(cert_cmd, timeout=5)
                        
                        if cert_result.get('success'):
                            cert_info = {'path': cert_path}
                            for line in cert_result['stdout'].splitlines():
                                if line.startswith('subject='):
                                    cert_info['subject'] = line.replace('subject=', '')
                                elif line.startswith('notBefore='):
                                    cert_info['not_before'] = line.replace('notBefore=', '')
                                elif line.startswith('notAfter='):
                                    cert_info['not_after'] = line.replace('notAfter=', '')
                            
                            certificates.append(cert_info)
        
        return certificates[:50]  # Limit results
    
    def _collect_ssh_configuration(self) -> Dict[str, Any]:
        """Collect SSH server configuration"""
        ssh_config = {}
        
        commands = {
            'sshd_config': 'cat /etc/ssh/sshd_config 2>/dev/null',
            'ssh_status': 'systemctl status ssh 2>/dev/null || systemctl status sshd 2>/dev/null',
            'authorized_keys': 'find /home /root -name "authorized_keys" 2>/dev/null | wc -l',
            'ssh_keys': 'find /etc/ssh -name "ssh_host_*" 2>/dev/null'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # Parse sshd_config
        if results.get('sshd_config', {}).get('success'):
            config_items = {}
            for line in results['sshd_config']['stdout'].splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    if ' ' in line:
                        key, value = line.split(None, 1)
                        config_items[key.lower()] = value
            
            # Extract important security settings
            ssh_config['port'] = config_items.get('port', '22')
            ssh_config['root_login'] = config_items.get('permitrootlogin', 'unknown')
            ssh_config['password_auth'] = config_items.get('passwordauthentication', 'unknown')
            ssh_config['pubkey_auth'] = config_items.get('pubkeyauthentication', 'unknown')
            ssh_config['x11_forwarding'] = config_items.get('x11forwarding', 'unknown')
            ssh_config['protocol'] = config_items.get('protocol', 'unknown')
        
        # SSH service status
        if results.get('ssh_status', {}).get('success'):
            if 'active (running)' in results['ssh_status']['stdout']:
                ssh_config['status'] = 'running'
            else:
                ssh_config['status'] = 'stopped'
        
        # Authorized keys count
        if results.get('authorized_keys', {}).get('success'):
            ssh_config['authorized_keys_files'] = int(results['authorized_keys']['stdout'].strip())
        
        # Host keys
        if results.get('ssh_keys', {}).get('success'):
            ssh_config['host_keys'] = results['ssh_keys']['stdout'].splitlines()
        
        return ssh_config
    
    def _collect_fail2ban_info(self) -> Dict[str, Any]:
        """Collect Fail2ban information"""
        fail2ban_info = {}
        
        commands = {
            'status': 'fail2ban-client status 2>/dev/null',
            'version': 'fail2ban-client version 2>/dev/null',
            'jails': 'fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2',
            'service_status': 'systemctl status fail2ban 2>/dev/null'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        if results.get('version', {}).get('success'):
            fail2ban_info['version'] = results['version']['stdout'].strip()
        
        if results.get('service_status', {}).get('success'):
            if 'active (running)' in results['service_status']['stdout']:
                fail2ban_info['status'] = 'running'
            else:
                fail2ban_info['status'] = 'stopped'
        
        if results.get('jails', {}).get('success'):
            jails = results['jails']['stdout'].strip().replace(',', ' ').split()
            fail2ban_info['active_jails'] = [jail.strip() for jail in jails if jail.strip()]
        
        return fail2ban_info
    
    def _collect_apparmor_info(self) -> Dict[str, Any]:
        """Collect AppArmor information"""
        apparmor_info = {}
        
        commands = {
            'status': 'aa-status 2>/dev/null',
            'enabled': 'systemctl is-enabled apparmor 2>/dev/null',
            'profiles': 'ls /etc/apparmor.d/ 2>/dev/null | wc -l'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        if results.get('status', {}).get('success'):
            status_output = results['status']['stdout']
            apparmor_info['profiles_loaded'] = status_output.count('profiles are loaded')
            apparmor_info['profiles_enforced'] = status_output.count('profiles are in enforce mode')
            apparmor_info['profiles_complain'] = status_output.count('profiles are in complain mode')
        
        if results.get('enabled', {}).get('success'):
            apparmor_info['service_enabled'] = results['enabled']['stdout'].strip() == 'enabled'
        
        if results.get('profiles', {}).get('success'):
            apparmor_info['total_profiles'] = int(results['profiles']['stdout'].strip())
        
        return apparmor_info
    
    def _collect_selinux_info(self) -> Dict[str, Any]:
        """Collect SELinux information"""
        selinux_info = {}
        
        commands = {
            'status': 'sestatus 2>/dev/null',
            'getenforce': 'getenforce 2>/dev/null',
            'config': 'cat /etc/selinux/config 2>/dev/null'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        if results.get('getenforce', {}).get('success'):
            mode = results['getenforce']['stdout'].strip().lower()
            selinux_info['current_mode'] = mode
        
        if results.get('status', {}).get('success'):
            status_lines = results['status']['stdout'].splitlines()
            for line in status_lines:
                if 'SELinux status:' in line:
                    selinux_info['status'] = line.split(':')[1].strip()
                elif 'Current mode:' in line:
                    selinux_info['current_mode'] = line.split(':')[1].strip()
                elif 'Mode from config file:' in line:
                    selinux_info['config_mode'] = line.split(':')[1].strip()
        
        if results.get('config', {}).get('success'):
            for line in results['config']['stdout'].splitlines():
                if line.startswith('SELINUX='):
                    selinux_info['config_setting'] = line.split('=')[1]
        
        return selinux_info
    
    def _collect_sudo_configuration(self) -> Dict[str, Any]:
        """Collect sudo configuration"""
        sudo_config = {}
        
        commands = {
            'sudoers': 'cat /etc/sudoers 2>/dev/null | grep -v "^#" | grep -v "^$"',
            'sudoers_d': 'ls -la /etc/sudoers.d/ 2>/dev/null',
            'sudo_group': 'getent group sudo 2>/dev/null || getent group wheel 2>/dev/null'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # Parse main sudoers file
        if results.get('sudoers', {}).get('success'):
            sudo_rules = []
            for line in results['sudoers']['stdout'].splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    sudo_rules.append(line)
            sudo_config['sudoers_rules'] = sudo_rules[:20]  # Limit
        
        # Count sudoers.d files
        if results.get('sudoers_d', {}).get('success'):
            files = []
            for line in results['sudoers_d']['stdout'].splitlines():
                if not line.startswith('total') and not line.startswith('d'):
                    parts = line.split()
                    if len(parts) >= 9:
                        files.append(parts[8])
            sudo_config['sudoers_d_files'] = files
        
        # Sudo group members
        if results.get('sudo_group', {}).get('success'):
            group_line = results['sudo_group']['stdout'].strip()
            if ':' in group_line:
                parts = group_line.split(':')
                if len(parts) >= 4 and parts[3]:
                    sudo_config['sudo_users'] = parts[3].split(',')
        
        return sudo_config
    
    def _collect_iptables_summary(self) -> Dict[str, Any]:
        """Collect iptables security summary"""
        iptables_info = {}
        
        commands = {
            'input_policy': 'iptables -L INPUT -n | head -1',
            'output_policy': 'iptables -L OUTPUT -n | head -1',
            'forward_policy': 'iptables -L FORWARD -n | head -1',
            'rule_count': 'iptables -L -n | grep -c "^ACCEPT\\|^DROP\\|^REJECT"',
            'drop_rules': 'iptables -L -n | grep -c "^DROP"'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # Extract chain policies
        for chain in ['input', 'output', 'forward']:
            policy_key = f'{chain}_policy'
            if results.get(policy_key, {}).get('success'):
                policy_line = results[policy_key]['stdout']
                if 'policy' in policy_line:
                    policy = policy_line.split('policy')[1].split()[0]
                    iptables_info[f'{chain}_policy'] = policy
        
        # Rule counts
        if results.get('rule_count', {}).get('success'):
            iptables_info['total_rules'] = int(results['rule_count']['stdout'].strip())
        
        if results.get('drop_rules', {}).get('success'):
            iptables_info['drop_rules'] = int(results['drop_rules']['stdout'].strip())
        
        return iptables_info
    
    def _collect_open_ports(self) -> List[Dict]:
        """Collect open ports and services"""
        open_ports = []
        
        # Use ss or netstat to find listening ports
        cmd = 'ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null'
        result = self.discovery.execute_command(cmd, timeout=10)
        
        if result.get('success'):
            for line in result['stdout'].splitlines():
                if 'LISTEN' in line or 'udp' in line.lower():
                    parts = line.split()
                    if len(parts) >= 5:
                        local_addr = parts[4] if 'LISTEN' in line else parts[3]
                        if ':' in local_addr:
                            addr_parts = local_addr.rsplit(':', 1)
                            port = addr_parts[1]
                            
                            # Determine if port is public
                            is_public = not any(addr_parts[0].startswith(x) for x in ['127.', '::1', 'localhost'])
                            
                            port_info = {
                                'port': port,
                                'protocol': parts[0].lower(),
                                'address': addr_parts[0],
                                'public': is_public
                            }
                            
                            # Try to identify the service
                            well_known_ports = {
                                '22': 'SSH',
                                '80': 'HTTP',
                                '443': 'HTTPS',
                                '25': 'SMTP',
                                '53': 'DNS',
                                '3306': 'MySQL',
                                '5432': 'PostgreSQL',
                                '6379': 'Redis',
                                '27017': 'MongoDB',
                                '9200': 'Elasticsearch'
                            }
                            
                            port_info['service'] = well_known_ports.get(port, 'Unknown')
                            open_ports.append(port_info)
        
        return open_ports[:50]  # Limit results
    
    def _check_security_updates(self) -> Dict[str, Any]:
        """Check for available security updates"""
        updates_info = {}
        
        commands = {
            'apt_security': 'apt list --upgradable 2>/dev/null | grep -i security | wc -l',
            'yum_security': 'yum --security check-update 2>/dev/null | grep -c "packages"',
            'unattended_upgrades': 'systemctl status unattended-upgrades 2>/dev/null'
        }
        
        results = self.discovery.execute_commands_parallel(commands, timeout=30)
        
        # APT security updates (Debian/Ubuntu)
        if results.get('apt_security', {}).get('success'):
            count = results['apt_security']['stdout'].strip()
            if count.isdigit():
                updates_info['apt_security_updates'] = int(count)
        
        # YUM security updates (RedHat/CentOS)
        if results.get('yum_security', {}).get('success'):
            count = results['yum_security']['stdout'].strip()
            if count.isdigit():
                updates_info['yum_security_updates'] = int(count)
        
        # Unattended upgrades status
        if results.get('unattended_upgrades', {}).get('success'):
            if 'active (running)' in results['unattended_upgrades']['stdout']:
                updates_info['automatic_updates'] = 'enabled'
            else:
                updates_info['automatic_updates'] = 'disabled'
        
        return updates_info