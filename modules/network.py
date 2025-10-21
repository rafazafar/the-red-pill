import re
import json
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class NetworkModule:
    def __init__(self, discovery):
        self.discovery = discovery
    
    def collect(self) -> Dict[str, Any]:
        """Collect comprehensive network information"""
        logger.info("Collecting network information...")
        
        commands = {
            'interfaces': 'ip -j addr show 2>/dev/null || ip addr show',
            'routes': 'ip -j route show 2>/dev/null || ip route show',
            'route_rules': 'ip rule show',
            'dns': 'cat /etc/resolv.conf',
            'hosts': 'cat /etc/hosts',
            'hostname_config': 'hostnamectl 2>/dev/null || cat /etc/hostname',
            'listening_ports': 'ss -tulpn 2>/dev/null || netstat -tulpn',
            'all_connections': 'ss -tan 2>/dev/null || netstat -tan',
            'network_stats': 'ss -s 2>/dev/null || netstat -s',
            'arp_cache': 'ip neigh show 2>/dev/null || arp -a'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        network_info = {
            'interfaces': self._parse_interfaces(results.get('interfaces', {})),
            'routes': self._parse_routes(results.get('routes', {})),
            'dns': self._parse_dns(results.get('dns', {})),
            'hosts': self._parse_hosts(results.get('hosts', {})),
            'listening_ports': self._parse_listening_ports(results.get('listening_ports', {})),
            'connections': self._parse_connections(results.get('all_connections', {})),
            'arp_cache': self._parse_arp(results.get('arp_cache', {}))
        }
        
        # Collect firewall information
        firewall_info = self._collect_firewall_info()
        network_info['firewall'] = firewall_info
        
        # Collect reverse proxy configurations
        proxy_info = self._collect_reverse_proxy_info()
        network_info['reverse_proxies'] = proxy_info
        
        # Collect VPN configurations
        vpn_info = self._collect_vpn_info()
        network_info['vpn'] = vpn_info
        
        return network_info
    
    def _parse_interfaces(self, result: Dict) -> List[Dict]:
        """Parse network interfaces"""
        interfaces = []
        
        if not result.get('success'):
            return interfaces
        
        output = result['stdout']
        
        # Try JSON format first
        if output.startswith('['):
            try:
                json_data = json.loads(output)
                for iface in json_data:
                    interface_info = {
                        'name': iface.get('ifname'),
                        'index': iface.get('ifindex'),
                        'mtu': iface.get('mtu'),
                        'state': iface.get('operstate'),
                        'mac': iface.get('address'),
                        'addresses': []
                    }
                    
                    for addr_info in iface.get('addr_info', []):
                        interface_info['addresses'].append({
                            'family': addr_info.get('family'),
                            'address': addr_info.get('local'),
                            'prefix': addr_info.get('prefixlen'),
                            'broadcast': addr_info.get('broadcast')
                        })
                    
                    interfaces.append(interface_info)
                return interfaces
            except:
                pass
        
        # Parse text format
        current_iface = None
        for line in output.splitlines():
            # Interface line (starts with number)
            match = re.match(r'^(\d+):\s+(\S+):\s+<(.+?)>\s+mtu\s+(\d+)', line)
            if match:
                if current_iface:
                    interfaces.append(current_iface)
                
                current_iface = {
                    'index': int(match.group(1)),
                    'name': match.group(2).rstrip(':'),
                    'flags': match.group(3).split(','),
                    'mtu': int(match.group(4)),
                    'addresses': []
                }
                
                # Extract state
                if 'state' in line:
                    state_match = re.search(r'state\s+(\S+)', line)
                    if state_match:
                        current_iface['state'] = state_match.group(1)
            
            # MAC address line
            elif current_iface and 'link/ether' in line:
                mac_match = re.search(r'link/ether\s+([0-9a-f:]+)', line)
                if mac_match:
                    current_iface['mac'] = mac_match.group(1)
            
            # IP address line
            elif current_iface and ('inet ' in line or 'inet6 ' in line):
                addr_match = re.search(r'(inet6?)\s+(\S+)', line)
                if addr_match:
                    family = 'ipv4' if addr_match.group(1) == 'inet' else 'ipv6'
                    address_parts = addr_match.group(2).split('/')
                    addr_info = {
                        'family': family,
                        'address': address_parts[0],
                        'prefix': int(address_parts[1]) if len(address_parts) > 1 else None
                    }
                    
                    # Extract broadcast
                    if 'brd' in line:
                        brd_match = re.search(r'brd\s+(\S+)', line)
                        if brd_match:
                            addr_info['broadcast'] = brd_match.group(1)
                    
                    current_iface['addresses'].append(addr_info)
        
        if current_iface:
            interfaces.append(current_iface)
        
        return interfaces
    
    def _parse_routes(self, result: Dict) -> List[Dict]:
        """Parse routing table"""
        routes = []
        
        if not result.get('success'):
            return routes
        
        output = result['stdout']
        
        # Try JSON format first
        if output.startswith('['):
            try:
                return json.loads(output)
            except:
                pass
        
        # Parse text format
        for line in output.splitlines():
            if not line.strip():
                continue
            
            route_info = {}
            parts = line.split()
            
            if parts[0] == 'default':
                route_info['destination'] = 'default'
                idx = 1
            else:
                route_info['destination'] = parts[0]
                idx = 1
            
            # Parse route attributes
            while idx < len(parts):
                if parts[idx] == 'via':
                    route_info['gateway'] = parts[idx + 1]
                    idx += 2
                elif parts[idx] == 'dev':
                    route_info['interface'] = parts[idx + 1]
                    idx += 2
                elif parts[idx] == 'proto':
                    route_info['protocol'] = parts[idx + 1]
                    idx += 2
                elif parts[idx] == 'src':
                    route_info['source'] = parts[idx + 1]
                    idx += 2
                elif parts[idx] == 'metric':
                    route_info['metric'] = int(parts[idx + 1])
                    idx += 2
                else:
                    idx += 1
            
            routes.append(route_info)
        
        return routes
    
    def _parse_dns(self, result: Dict) -> Dict[str, Any]:
        """Parse DNS configuration"""
        dns_info = {
            'nameservers': [],
            'search_domains': [],
            'options': []
        }
        
        if not result.get('success'):
            return dns_info
        
        for line in result['stdout'].splitlines():
            line = line.strip()
            if line.startswith('nameserver'):
                ns = line.split(None, 1)[1] if len(line.split()) > 1 else None
                if ns:
                    dns_info['nameservers'].append(ns)
            elif line.startswith('search'):
                domains = line.split()[1:] if len(line.split()) > 1 else []
                dns_info['search_domains'].extend(domains)
            elif line.startswith('domain'):
                domain = line.split(None, 1)[1] if len(line.split()) > 1 else None
                if domain and domain not in dns_info['search_domains']:
                    dns_info['search_domains'].append(domain)
            elif line.startswith('options'):
                opts = line.split()[1:] if len(line.split()) > 1 else []
                dns_info['options'].extend(opts)
        
        return dns_info
    
    def _parse_hosts(self, result: Dict) -> List[Dict]:
        """Parse /etc/hosts file"""
        hosts = []
        
        if not result.get('success'):
            return hosts
        
        for line in result['stdout'].splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                hosts.append({
                    'ip': parts[0],
                    'hostnames': parts[1:]
                })
        
        return hosts
    
    def _parse_listening_ports(self, result: Dict) -> List[Dict]:
        """Parse listening ports"""
        ports = []
        
        if not result.get('success'):
            return ports
        
        output = result['stdout']
        
        for line in output.splitlines():
            # Skip headers and empty lines
            if not line.strip() or line.startswith('Proto') or line.startswith('Active'):
                continue
            
            parts = line.split()
            if len(parts) < 4:
                continue
            
            # ss format or netstat format
            if parts[0] in ['tcp', 'tcp6', 'udp', 'udp6']:
                port_info = {
                    'protocol': parts[0],
                    'state': parts[1] if len(parts) > 5 else 'LISTEN'
                }
                
                # Parse local address
                if len(parts) >= 5:
                    local_addr = parts[4] if 'LISTEN' in parts else parts[3]
                    if ':' in local_addr:
                        addr_parts = local_addr.rsplit(':', 1)
                        port_info['local_address'] = addr_parts[0]
                        port_info['local_port'] = addr_parts[1]
                
                # Parse foreign address
                if len(parts) >= 6:
                    foreign_addr = parts[5] if 'LISTEN' in parts else parts[4]
                    if ':' in foreign_addr:
                        addr_parts = foreign_addr.rsplit(':', 1)
                        port_info['foreign_address'] = addr_parts[0]
                        port_info['foreign_port'] = addr_parts[1]
                
                # Parse process info
                for part in parts:
                    if 'users:' in part:
                        # ss format: users:(("nginx",pid=1234,fd=5))
                        match = re.search(r'"([^"]+)".*pid=(\d+)', part)
                        if match:
                            port_info['process'] = match.group(1)
                            port_info['pid'] = int(match.group(2))
                    elif '/' in part and part[0].isdigit():
                        # netstat format: 1234/nginx
                        proc_parts = part.split('/')
                        port_info['pid'] = int(proc_parts[0])
                        port_info['process'] = proc_parts[1]
                
                if 'LISTEN' in line or 'UNCONN' in line:
                    ports.append(port_info)
        
        return ports
    
    def _parse_connections(self, result: Dict) -> Dict[str, Any]:
        """Parse network connections"""
        connections = {
            'established': 0,
            'time_wait': 0,
            'close_wait': 0,
            'syn_sent': 0,
            'syn_recv': 0,
            'fin_wait': 0,
            'total': 0
        }
        
        if not result.get('success'):
            return connections
        
        for line in result['stdout'].splitlines():
            if 'ESTABLISHED' in line:
                connections['established'] += 1
            elif 'TIME_WAIT' in line:
                connections['time_wait'] += 1
            elif 'CLOSE_WAIT' in line:
                connections['close_wait'] += 1
            elif 'SYN_SENT' in line:
                connections['syn_sent'] += 1
            elif 'SYN_RECV' in line:
                connections['syn_recv'] += 1
            elif 'FIN_WAIT' in line:
                connections['fin_wait'] += 1
        
        connections['total'] = sum(v for k, v in connections.items() if k != 'total')
        
        return connections
    
    def _parse_arp(self, result: Dict) -> List[Dict]:
        """Parse ARP cache"""
        arp_entries = []
        
        if not result.get('success'):
            return arp_entries
        
        for line in result['stdout'].splitlines():
            # ip neigh format
            if 'lladdr' in line:
                parts = line.split()
                if len(parts) >= 5:
                    arp_entries.append({
                        'ip': parts[0],
                        'interface': parts[2],
                        'mac': parts[4],
                        'state': parts[-1]
                    })
            # arp -a format
            elif '(' in line and ')' in line:
                match = re.search(r'([^\s]+)\s+\(([^)]+)\)\s+at\s+([0-9a-f:]+)', line)
                if match:
                    arp_entries.append({
                        'hostname': match.group(1),
                        'ip': match.group(2),
                        'mac': match.group(3)
                    })
        
        return arp_entries
    
    def _collect_firewall_info(self) -> Dict[str, Any]:
        """Collect firewall configuration"""
        firewall_info = {}
        
        commands = {
            'iptables': 'iptables -L -n -v 2>/dev/null || true',
            'iptables_save': 'iptables-save 2>/dev/null || true',
            'nftables': 'nft list ruleset 2>/dev/null || true',
            'ufw': 'ufw status verbose 2>/dev/null || true',
            'firewalld': 'firewall-cmd --list-all 2>/dev/null || true',
            'firewalld_zones': 'firewall-cmd --get-active-zones 2>/dev/null || true'
        }
        
        results = self.discovery.execute_commands_parallel(commands, timeout=10)
        
        # Check which firewall is active
        if results.get('iptables', {}).get('success') and 'Chain' in results['iptables']['stdout']:
            firewall_info['iptables'] = {
                'active': True,
                'rules_summary': self._parse_iptables_summary(results['iptables']['stdout']),
                'raw_output': results.get('iptables_save', {}).get('stdout', '')[:5000]  # Limit size
            }
        
        if results.get('nftables', {}).get('success') and results['nftables']['stdout'].strip():
            firewall_info['nftables'] = {
                'active': True,
                'rules': results['nftables']['stdout'][:5000]  # Limit size
            }
        
        if results.get('ufw', {}).get('success') and 'Status:' in results['ufw']['stdout']:
            firewall_info['ufw'] = self._parse_ufw(results['ufw']['stdout'])
        
        if results.get('firewalld', {}).get('success') and results['firewalld']['stdout'].strip():
            firewall_info['firewalld'] = {
                'active': True,
                'configuration': results['firewalld']['stdout'],
                'zones': results.get('firewalld_zones', {}).get('stdout', '')
            }
        
        return firewall_info
    
    def _parse_iptables_summary(self, output: str) -> Dict[str, Any]:
        """Parse iptables output for summary"""
        summary = {
            'chains': {},
            'total_rules': 0
        }
        
        current_table = 'filter'
        for line in output.splitlines():
            if line.startswith('Chain'):
                parts = line.split()
                if len(parts) >= 2:
                    chain_name = parts[1]
                    policy = None
                    if 'policy' in line:
                        policy_idx = parts.index('policy') + 1
                        if policy_idx < len(parts):
                            policy = parts[policy_idx]
                    
                    summary['chains'][chain_name] = {
                        'policy': policy,
                        'rules': 0
                    }
            elif line.strip() and not line.startswith('Chain') and not line.startswith('pkts'):
                summary['total_rules'] += 1
                # Count rules per chain (simplified)
                for chain in summary['chains']:
                    if chain in ['INPUT', 'OUTPUT', 'FORWARD']:
                        summary['chains'][chain]['rules'] = summary['chains'][chain].get('rules', 0) + 1
        
        return summary
    
    def _parse_ufw(self, output: str) -> Dict[str, Any]:
        """Parse UFW status"""
        ufw_info = {
            'active': False,
            'rules': []
        }
        
        for line in output.splitlines():
            if 'Status:' in line:
                ufw_info['active'] = 'active' in line.lower()
            elif line.strip() and not line.startswith('--') and not line.startswith('Status'):
                # Parse rule lines
                if 'ALLOW' in line or 'DENY' in line or 'REJECT' in line:
                    ufw_info['rules'].append(line.strip())
        
        return ufw_info
    
    def _collect_reverse_proxy_info(self) -> Dict[str, Any]:
        """Collect reverse proxy configurations"""
        proxy_info = {}
        
        commands = {
            'nginx_check': 'nginx -v 2>&1 || true',
            'nginx_config': 'nginx -T 2>/dev/null || cat /etc/nginx/nginx.conf 2>/dev/null || true',
            'nginx_sites': 'ls -la /etc/nginx/sites-enabled/ 2>/dev/null || true',
            'apache_check': 'apache2 -v 2>/dev/null || httpd -v 2>/dev/null || true',
            'apache_modules': 'apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null || true',
            'apache_sites': 'apache2ctl -S 2>/dev/null || httpd -S 2>/dev/null || true',
            'haproxy_check': 'haproxy -v 2>/dev/null || true',
            'haproxy_config': 'cat /etc/haproxy/haproxy.cfg 2>/dev/null || true',
            'caddy_check': 'caddy version 2>/dev/null || true',
            'caddy_config': 'cat /etc/caddy/Caddyfile 2>/dev/null || true',
            'traefik_check': 'traefik version 2>/dev/null || true'
        }
        
        results = self.discovery.execute_commands_parallel(commands, timeout=10)
        
        # Nginx
        if results.get('nginx_check', {}).get('success') and 'nginx' in results['nginx_check']['stdout'].lower():
            nginx_info = {
                'installed': True,
                'version': results['nginx_check']['stdout'].strip()
            }
            
            if results.get('nginx_config', {}).get('success'):
                # Extract key configuration items
                config = results['nginx_config']['stdout']
                nginx_info['server_blocks'] = config.count('server {')
                nginx_info['upstream_blocks'] = config.count('upstream ')
                nginx_info['proxy_pass_count'] = config.count('proxy_pass')
                
                # Extract server names and proxy passes
                nginx_info['server_names'] = list(set(re.findall(r'server_name\s+([^;]+);', config)))
                nginx_info['proxy_destinations'] = list(set(re.findall(r'proxy_pass\s+([^;]+);', config)))
            
            if results.get('nginx_sites', {}).get('success'):
                nginx_info['enabled_sites'] = []
                for line in results['nginx_sites']['stdout'].splitlines():
                    if not line.startswith('total') and '->' not in line and '.' not in line[:1]:
                        parts = line.split()
                        if len(parts) >= 9:
                            nginx_info['enabled_sites'].append(parts[-1])
            
            proxy_info['nginx'] = nginx_info
        
        # Apache
        if results.get('apache_check', {}).get('success') and ('apache' in results['apache_check']['stdout'].lower() or 'server version' in results['apache_check']['stdout'].lower()):
            apache_info = {
                'installed': True,
                'version': results['apache_check']['stdout'].strip()
            }
            
            if results.get('apache_modules', {}).get('success'):
                apache_info['proxy_modules'] = []
                for line in results['apache_modules']['stdout'].splitlines():
                    if 'proxy' in line.lower():
                        module_name = line.split()[0] if line.split() else line
                        apache_info['proxy_modules'].append(module_name)
            
            if results.get('apache_sites', {}).get('success'):
                apache_info['vhosts'] = []
                for line in results['apache_sites']['stdout'].splitlines():
                    if 'port' in line.lower() and 'namevhost' in line.lower():
                        apache_info['vhosts'].append(line.strip())
            
            proxy_info['apache'] = apache_info
        
        # HAProxy
        if results.get('haproxy_check', {}).get('success') and 'haproxy' in results['haproxy_check']['stdout'].lower():
            haproxy_info = {
                'installed': True,
                'version': results['haproxy_check']['stdout'].strip()
            }
            
            if results.get('haproxy_config', {}).get('success'):
                config = results['haproxy_config']['stdout']
                haproxy_info['frontend_count'] = config.count('frontend ')
                haproxy_info['backend_count'] = config.count('backend ')
                haproxy_info['server_count'] = config.count('server ')
            
            proxy_info['haproxy'] = haproxy_info
        
        # Caddy
        if results.get('caddy_check', {}).get('success') and 'caddy' in results['caddy_check']['stdout'].lower():
            caddy_info = {
                'installed': True,
                'version': results['caddy_check']['stdout'].strip()
            }
            
            if results.get('caddy_config', {}).get('success'):
                caddy_info['config_preview'] = results['caddy_config']['stdout'][:1000]
            
            proxy_info['caddy'] = caddy_info
        
        # Traefik
        if results.get('traefik_check', {}).get('success') and 'traefik' in results['traefik_check']['stdout'].lower():
            proxy_info['traefik'] = {
                'installed': True,
                'version': results['traefik_check']['stdout'].strip()
            }
        
        return proxy_info
    
    def _collect_vpn_info(self) -> Dict[str, Any]:
        """Collect VPN configuration"""
        vpn_info = {}
        
        commands = {
            'openvpn_check': 'openvpn --version 2>/dev/null | head -1 || true',
            'openvpn_configs': 'ls -la /etc/openvpn/ 2>/dev/null || true',
            'wireguard_check': 'wg version 2>/dev/null || true',
            'wireguard_interfaces': 'wg show interfaces 2>/dev/null || true',
            'ipsec_check': 'ipsec version 2>/dev/null || strongswan version 2>/dev/null || true',
            'ipsec_status': 'ipsec status 2>/dev/null || true'
        }
        
        results = self.discovery.execute_commands_parallel(commands, timeout=10)
        
        # OpenVPN
        if results.get('openvpn_check', {}).get('success') and 'openvpn' in results['openvpn_check']['stdout'].lower():
            openvpn_info = {
                'installed': True,
                'version': results['openvpn_check']['stdout'].strip()
            }
            
            if results.get('openvpn_configs', {}).get('success'):
                configs = []
                for line in results['openvpn_configs']['stdout'].splitlines():
                    if '.conf' in line or '.ovpn' in line:
                        parts = line.split()
                        if len(parts) >= 9:
                            configs.append(parts[-1])
                openvpn_info['config_files'] = configs
            
            vpn_info['openvpn'] = openvpn_info
        
        # WireGuard
        if results.get('wireguard_check', {}).get('success') and 'wireguard' in results['wireguard_check']['stdout'].lower():
            wg_info = {
                'installed': True,
                'version': results['wireguard_check']['stdout'].strip()
            }
            
            if results.get('wireguard_interfaces', {}).get('success'):
                wg_info['interfaces'] = results['wireguard_interfaces']['stdout'].strip().split()
            
            vpn_info['wireguard'] = wg_info
        
        # IPSec
        if results.get('ipsec_check', {}).get('success') and ('ipsec' in results['ipsec_check']['stdout'].lower() or 'strongswan' in results['ipsec_check']['stdout'].lower()):
            ipsec_info = {
                'installed': True,
                'version': results['ipsec_check']['stdout'].strip()
            }
            
            if results.get('ipsec_status', {}).get('success'):
                ipsec_info['status'] = 'Active' if 'established' in results['ipsec_status']['stdout'].lower() else 'Inactive'
            
            vpn_info['ipsec'] = ipsec_info
        
        return vpn_info