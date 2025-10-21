import re
import json
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class ServicesModule:
    def __init__(self, discovery):
        self.discovery = discovery
    
    def collect(self) -> Dict[str, Any]:
        """Collect comprehensive service information"""
        logger.info("Collecting service information...")
        
        services = {
            'init_system': self._detect_init_system(),
            'systemd': self._collect_systemd_services(),
            'sysvinit': self._collect_sysvinit_services(),
            'upstart': self._collect_upstart_services(),
            'cron': self._collect_cron_jobs(),
            'supervisord': self._collect_supervisord_services(),
            'process_managers': self._collect_process_managers(),
            'startup_scripts': self._collect_startup_scripts()
        }
        
        return services
    
    def _detect_init_system(self) -> str:
        """Detect the init system in use"""
        commands = {
            'systemd': 'systemctl --version 2>/dev/null | head -1',
            'upstart': 'init --version 2>/dev/null | head -1',
            'sysvinit': 'ls /etc/init.d 2>/dev/null | head -1',
            'openrc': 'rc-status --version 2>/dev/null | head -1'
        }
        
        results = self.discovery.execute_commands_parallel(commands, timeout=5)
        
        if results.get('systemd', {}).get('success') and 'systemd' in results['systemd']['stdout']:
            return 'systemd'
        elif results.get('upstart', {}).get('success') and 'upstart' in results['upstart']['stdout']:
            return 'upstart'
        elif results.get('openrc', {}).get('success') and 'openrc' in results['openrc']['stdout'].lower():
            return 'openrc'
        elif results.get('sysvinit', {}).get('success') and results['sysvinit']['stdout']:
            return 'sysvinit'
        else:
            return 'unknown'
    
    def _collect_systemd_services(self) -> List[Dict]:
        """Collect systemd service information"""
        services = []
        
        commands = {
            'list_services': 'systemctl list-units --type=service --all --no-pager --output=json 2>/dev/null || systemctl list-units --type=service --all --no-pager',
            'list_timers': 'systemctl list-timers --all --no-pager',
            'failed_services': 'systemctl --failed --no-pager'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # Parse service list
        if results.get('list_services', {}).get('success'):
            output = results['list_services']['stdout']
            
            # Try JSON format first
            if output.startswith('['):
                try:
                    services = json.loads(output)
                except:
                    pass
            else:
                # Parse text format
                for line in output.splitlines():
                    if '.service' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            service = {
                                'name': parts[0].replace('.service', ''),
                                'load': parts[1] if len(parts) > 1 else '',
                                'active': parts[2] if len(parts) > 2 else '',
                                'sub': parts[3] if len(parts) > 3 else '',
                                'description': ' '.join(parts[4:]) if len(parts) > 4 else ''
                            }
                            services.append(service)
        
        # Add timer information
        if results.get('list_timers', {}).get('success'):
            timer_info = []
            for line in results['list_timers']['stdout'].splitlines():
                if '.timer' in line:
                    timer_info.append(line.strip())
            if timer_info:
                services.append({
                    'timers': timer_info[:20]  # Limit
                })
        
        # Add failed services
        if results.get('failed_services', {}).get('success'):
            failed = []
            for line in results['failed_services']['stdout'].splitlines():
                if '.service' in line:
                    parts = line.split()
                    if parts:
                        failed.append(parts[0])
            if failed:
                services.append({
                    'failed_services': failed
                })
        
        return services
    
    def _collect_sysvinit_services(self) -> List[Dict]:
        """Collect SysV init services"""
        services = []
        
        commands = {
            'list_initd': 'ls -la /etc/init.d/ 2>/dev/null',
            'chkconfig': 'chkconfig --list 2>/dev/null',
            'service_status': 'service --status-all 2>/dev/null',
            'rc_update': 'rc-update show 2>/dev/null'
        }
        
        results = self.discovery.execute_commands_parallel(commands, timeout=10)
        
        # Parse init.d scripts
        if results.get('list_initd', {}).get('success'):
            for line in results['list_initd']['stdout'].splitlines():
                if not line.startswith('total') and not line.startswith('d'):
                    parts = line.split()
                    if len(parts) >= 9:
                        script_name = parts[8]
                        if not script_name.startswith('.') and script_name not in ['README', 'rc', 'rcS', 'functions']:
                            services.append({
                                'name': script_name,
                                'type': 'init.d'
                            })
        
        # Parse chkconfig output
        if results.get('chkconfig', {}).get('success'):
            for line in results['chkconfig']['stdout'].splitlines():
                if '\t' in line:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        services.append({
                            'name': parts[0],
                            'runlevels': parts[1:]
                        })
        
        # Parse service --status-all output
        if results.get('service_status', {}).get('success'):
            for line in results['service_status']['stdout'].splitlines():
                if '[' in line and ']' in line:
                    match = re.search(r'\[([ +\-?])\]\s+(.+)', line)
                    if match:
                        status = {'[+]': 'running', '[-]': 'stopped', '[?]': 'unknown'}.get(match.group(1), 'unknown')
                        services.append({
                            'name': match.group(2),
                            'status': status
                        })
        
        return services
    
    def _collect_upstart_services(self) -> List[Dict]:
        """Collect Upstart services"""
        services = []
        
        command = 'initctl list 2>/dev/null'
        result = self.discovery.execute_command(command, timeout=10)
        
        if result.get('success'):
            for line in result['stdout'].splitlines():
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        services.append({
                            'name': parts[0],
                            'status': ' '.join(parts[1:])
                        })
        
        return services
    
    def _collect_cron_jobs(self) -> Dict[str, Any]:
        """Collect cron job information"""
        cron_info = {}
        
        commands = {
            'system_crontab': 'cat /etc/crontab 2>/dev/null',
            'cron_d': 'ls -la /etc/cron.d/ 2>/dev/null',
            'cron_daily': 'ls -la /etc/cron.daily/ 2>/dev/null',
            'cron_hourly': 'ls -la /etc/cron.hourly/ 2>/dev/null',
            'cron_weekly': 'ls -la /etc/cron.weekly/ 2>/dev/null',
            'cron_monthly': 'ls -la /etc/cron.monthly/ 2>/dev/null',
            'user_crontabs': 'ls -la /var/spool/cron/crontabs/ 2>/dev/null || ls -la /var/spool/cron/ 2>/dev/null',
            'anacron': 'cat /etc/anacrontab 2>/dev/null'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # System crontab
        if results.get('system_crontab', {}).get('success'):
            cron_info['system_crontab'] = []
            for line in results['system_crontab']['stdout'].splitlines():
                if line.strip() and not line.startswith('#'):
                    cron_info['system_crontab'].append(line)
        
        # Cron directories
        for cron_dir in ['cron_d', 'cron_daily', 'cron_hourly', 'cron_weekly', 'cron_monthly']:
            if results.get(cron_dir, {}).get('success'):
                scripts = []
                for line in results[cron_dir]['stdout'].splitlines():
                    if not line.startswith('total') and not line.startswith('d'):
                        parts = line.split()
                        if len(parts) >= 9:
                            script = parts[8]
                            if not script.startswith('.'):
                                scripts.append(script)
                if scripts:
                    cron_info[cron_dir.replace('_', '.')] = scripts
        
        # User crontabs
        if results.get('user_crontabs', {}).get('success'):
            users = []
            for line in results['user_crontabs']['stdout'].splitlines():
                if not line.startswith('total') and not line.startswith('d'):
                    parts = line.split()
                    if len(parts) >= 9:
                        users.append(parts[8])
            if users:
                cron_info['user_crontabs'] = users
        
        # Anacron
        if results.get('anacron', {}).get('success'):
            anacron_jobs = []
            for line in results['anacron']['stdout'].splitlines():
                if line.strip() and not line.startswith('#'):
                    anacron_jobs.append(line)
            if anacron_jobs:
                cron_info['anacron'] = anacron_jobs
        
        return cron_info
    
    def _collect_supervisord_services(self) -> Dict[str, Any]:
        """Collect supervisord managed services"""
        supervisord_info = {}
        
        commands = {
            'status': 'supervisorctl status 2>/dev/null',
            'config': 'ls -la /etc/supervisor/conf.d/ 2>/dev/null || ls -la /etc/supervisord.d/ 2>/dev/null'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # Supervisord status
        if results.get('status', {}).get('success') and results['status']['stdout']:
            services = []
            for line in results['status']['stdout'].splitlines():
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        services.append({
                            'name': parts[0],
                            'status': parts[1],
                            'info': ' '.join(parts[2:])
                        })
            supervisord_info['services'] = services
        
        # Configuration files
        if results.get('config', {}).get('success'):
            configs = []
            for line in results['config']['stdout'].splitlines():
                if '.conf' in line or '.ini' in line:
                    parts = line.split()
                    if len(parts) >= 9:
                        configs.append(parts[8])
            if configs:
                supervisord_info['config_files'] = configs
        
        return supervisord_info
    
    def _collect_process_managers(self) -> Dict[str, Any]:
        """Collect information about various process managers"""
        managers = {}
        
        # PM2 (Node.js)
        pm2_cmd = 'pm2 list 2>/dev/null && pm2 jlist 2>/dev/null'
        pm2_result = self.discovery.execute_command(pm2_cmd, timeout=10)
        if pm2_result.get('success') and pm2_result['stdout']:
            managers['pm2'] = pm2_result['stdout'][:2000]  # Limit size
        
        # Forever (Node.js)
        forever_cmd = 'forever list 2>/dev/null'
        forever_result = self.discovery.execute_command(forever_cmd, timeout=10)
        if forever_result.get('success') and 'No forever processes' not in forever_result['stdout']:
            managers['forever'] = forever_result['stdout'][:1000]
        
        # Systemd user services
        user_services_cmd = 'systemctl --user list-units --type=service 2>/dev/null'
        user_result = self.discovery.execute_command(user_services_cmd, timeout=10)
        if user_result.get('success') and user_result['stdout']:
            user_services = []
            for line in user_result['stdout'].splitlines():
                if '.service' in line:
                    parts = line.split()
                    if parts:
                        user_services.append(parts[0])
            if user_services:
                managers['systemd_user'] = user_services[:20]  # Limit
        
        # Screen sessions
        screen_cmd = 'screen -ls 2>/dev/null'
        screen_result = self.discovery.execute_command(screen_cmd, timeout=5)
        if screen_result.get('success') and 'Socket' in screen_result['stdout']:
            screens = []
            for line in screen_result['stdout'].splitlines():
                if '\t' in line and '(' in line:
                    screens.append(line.strip())
            if screens:
                managers['screen_sessions'] = screens[:10]
        
        # Tmux sessions
        tmux_cmd = 'tmux ls 2>/dev/null'
        tmux_result = self.discovery.execute_command(tmux_cmd, timeout=5)
        if tmux_result.get('success') and tmux_result['stdout']:
            managers['tmux_sessions'] = tmux_result['stdout'].splitlines()[:10]
        
        return managers
    
    def _collect_startup_scripts(self) -> Dict[str, Any]:
        """Collect custom startup scripts and configurations"""
        startup_info = {}
        
        commands = {
            'rc_local': 'cat /etc/rc.local 2>/dev/null',
            'profile_d': 'ls -la /etc/profile.d/ 2>/dev/null',
            'systemd_system': 'ls -la /etc/systemd/system/*.service 2>/dev/null | head -50',
            'systemd_user': 'ls -la /etc/systemd/user/*.service 2>/dev/null | head -20',
            'xinetd': 'ls -la /etc/xinetd.d/ 2>/dev/null'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # rc.local
        if results.get('rc_local', {}).get('success'):
            rc_local = []
            for line in results['rc_local']['stdout'].splitlines():
                if line.strip() and not line.startswith('#'):
                    rc_local.append(line)
            if rc_local:
                startup_info['rc_local'] = rc_local
        
        # profile.d scripts
        if results.get('profile_d', {}).get('success'):
            scripts = []
            for line in results['profile_d']['stdout'].splitlines():
                if '.sh' in line:
                    parts = line.split()
                    if len(parts) >= 9:
                        scripts.append(parts[8])
            if scripts:
                startup_info['profile_scripts'] = scripts
        
        # Custom systemd services
        if results.get('systemd_system', {}).get('success'):
            custom_services = []
            for line in results['systemd_system']['stdout'].splitlines():
                if '.service' in line:
                    parts = line.split()
                    if len(parts) >= 9:
                        service = parts[8].split('/')[-1]
                        # Filter out common system services
                        if not any(x in service for x in ['systemd-', 'dbus', 'network', 'ssh', 'cron']):
                            custom_services.append(service)
            if custom_services:
                startup_info['custom_systemd_services'] = custom_services[:20]
        
        # xinetd services
        if results.get('xinetd', {}).get('success'):
            xinetd_services = []
            for line in results['xinetd']['stdout'].splitlines():
                if not line.startswith('total') and not line.startswith('d'):
                    parts = line.split()
                    if len(parts) >= 9:
                        xinetd_services.append(parts[8])
            if xinetd_services:
                startup_info['xinetd_services'] = xinetd_services
        
        return startup_info