import re
import json
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class SystemInfoModule:
    def __init__(self, discovery):
        self.discovery = discovery
    
    def collect(self) -> Dict[str, Any]:
        """Collect comprehensive system information"""
        logger.info("Collecting system information...")
        
        commands = {
            'hostname': 'hostname -f 2>/dev/null || hostname',
            'kernel': 'uname -srv',
            'architecture': 'uname -m',
            'uptime': 'uptime -p 2>/dev/null || uptime',
            'os_release': 'cat /etc/os-release 2>/dev/null',
            'lsb_release': 'lsb_release -a 2>/dev/null || true',
            'cpu_info': 'lscpu 2>/dev/null || cat /proc/cpuinfo',
            'memory': 'free -b 2>/dev/null || free -m',
            'disk_usage': 'df -hT',
            'block_devices': 'lsblk -J 2>/dev/null || lsblk',
            'dmidecode': 'dmidecode -t system,processor,memory 2>/dev/null || true',
            'virtualization': 'systemd-detect-virt 2>/dev/null || true',
            'selinux': 'sestatus 2>/dev/null || getenforce 2>/dev/null || echo "Not installed"',
            'timezone': 'timedatectl show 2>/dev/null || cat /etc/timezone 2>/dev/null || date +%Z'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        system_info = self._parse_system_info(results)
        
        # Collect additional hardware info
        hardware_commands = {
            'pci_devices': 'lspci 2>/dev/null || true',
            'usb_devices': 'lsusb 2>/dev/null || true',
            'network_interfaces': 'ip -j link show 2>/dev/null || ip link show',
            'loaded_modules': 'lsmod | head -20'
        }
        
        hardware_results = self.discovery.execute_commands_parallel(hardware_commands)
        system_info['hardware'] = self._parse_hardware_info(hardware_results)
        
        return system_info
    
    def _parse_system_info(self, results: Dict) -> Dict[str, Any]:
        """Parse system information from command outputs"""
        info = {}
        
        # Hostname
        if results.get('hostname', {}).get('success'):
            info['hostname'] = results['hostname']['stdout'].strip()
        
        # Kernel
        if results.get('kernel', {}).get('success'):
            info['kernel'] = results['kernel']['stdout'].strip()
        
        # Architecture
        if results.get('architecture', {}).get('success'):
            info['architecture'] = results['architecture']['stdout'].strip()
        
        # Uptime
        if results.get('uptime', {}).get('success'):
            info['uptime'] = results['uptime']['stdout'].strip()
        
        # OS Information
        if results.get('os_release', {}).get('success'):
            os_info = {}
            for line in results['os_release']['stdout'].splitlines():
                if '=' in line:
                    key, value = line.split('=', 1)
                    os_info[key.lower()] = value.strip('"')
            
            info['os_name'] = os_info.get('name', 'Unknown')
            info['os_version'] = os_info.get('version', os_info.get('version_id', 'Unknown'))
            info['os_id'] = os_info.get('id', 'Unknown')
            info['os_pretty_name'] = os_info.get('pretty_name', 'Unknown')
        
        # CPU Information
        if results.get('cpu_info', {}).get('success'):
            cpu_output = results['cpu_info']['stdout']
            info['cpu'] = self._parse_cpu_info(cpu_output)
        
        # Memory Information
        if results.get('memory', {}).get('success'):
            memory_output = results['memory']['stdout']
            info.update(self._parse_memory_info(memory_output))
        
        # Disk Usage
        if results.get('disk_usage', {}).get('success'):
            info['disk_usage'] = self._parse_disk_usage(results['disk_usage']['stdout'])
        
        # Block Devices
        if results.get('block_devices', {}).get('success'):
            block_output = results['block_devices']['stdout']
            if block_output.startswith('{'):
                try:
                    info['block_devices'] = json.loads(block_output)
                except:
                    info['block_devices_raw'] = block_output
            else:
                info['block_devices_raw'] = block_output
        
        # Virtualization
        if results.get('virtualization', {}).get('success'):
            virt = results['virtualization']['stdout'].strip()
            if virt and virt != 'none':
                info['virtualization'] = virt
        
        # SELinux
        if results.get('selinux', {}).get('success'):
            selinux = results['selinux']['stdout'].strip()
            if 'enforcing' in selinux.lower():
                info['selinux'] = 'Enforcing'
            elif 'permissive' in selinux.lower():
                info['selinux'] = 'Permissive'
            elif 'disabled' in selinux.lower():
                info['selinux'] = 'Disabled'
            else:
                info['selinux'] = 'Not installed'
        
        # Timezone
        if results.get('timezone', {}).get('success'):
            tz_output = results['timezone']['stdout']
            if 'Timezone=' in tz_output:
                info['timezone'] = tz_output.split('Timezone=')[1].strip()
            else:
                info['timezone'] = tz_output.strip()
        
        return info
    
    def _parse_cpu_info(self, output: str) -> Dict[str, Any]:
        """Parse CPU information from lscpu or /proc/cpuinfo"""
        cpu_info = {}
        
        if 'Architecture:' in output:  # lscpu format
            for line in output.splitlines():
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower().replace(' ', '_').replace('(s)', '')
                    value = value.strip()
                    
                    if 'cpu' in key or 'core' in key or 'socket' in key or 'thread' in key:
                        try:
                            cpu_info[key] = int(value)
                        except:
                            cpu_info[key] = value
                    elif 'model_name' in key or 'vendor' in key:
                        cpu_info[key] = value
                    elif 'mhz' in key or 'ghz' in key:
                        cpu_info[key] = value
        else:  # /proc/cpuinfo format
            processors = []
            current_proc = {}
            for line in output.splitlines():
                if line.strip() == '':
                    if current_proc:
                        processors.append(current_proc)
                        current_proc = {}
                elif ':' in line:
                    key, value = line.split(':', 1)
                    current_proc[key.strip().replace(' ', '_')] = value.strip()
            
            if current_proc:
                processors.append(current_proc)
            
            if processors:
                cpu_info['cpu_count'] = len(processors)
                cpu_info['model_name'] = processors[0].get('model_name', 'Unknown')
                cpu_info['vendor_id'] = processors[0].get('vendor_id', 'Unknown')
                cpu_info['cpu_mhz'] = processors[0].get('cpu_MHz', 'Unknown')
                cpu_info['cache_size'] = processors[0].get('cache_size', 'Unknown')
                
                # Count physical CPUs and cores
                physical_ids = set()
                core_ids = set()
                for proc in processors:
                    if 'physical_id' in proc:
                        physical_ids.add(proc['physical_id'])
                    if 'core_id' in proc:
                        core_ids.add(proc['core_id'])
                
                if physical_ids:
                    cpu_info['physical_cpus'] = len(physical_ids)
                if core_ids:
                    cpu_info['cpu_cores'] = len(core_ids)
        
        return cpu_info
    
    def _parse_memory_info(self, output: str) -> Dict[str, Any]:
        """Parse memory information from free command"""
        memory_info = {}
        
        for line in output.splitlines():
            if line.startswith('Mem:'):
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        # Check if output is in bytes (-b flag) or megabytes
                        total = int(parts[1])
                        used = int(parts[2])
                        free = int(parts[3])
                        
                        # If values are very large, they're in bytes
                        if total > 1000000:
                            memory_info['memory_total_bytes'] = total
                            memory_info['memory_used_bytes'] = used
                            memory_info['memory_free_bytes'] = free
                            memory_info['memory_total'] = f"{total / (1024**3):.2f} GB"
                            memory_info['memory_used'] = f"{used / (1024**3):.2f} GB"
                            memory_info['memory_free'] = f"{free / (1024**3):.2f} GB"
                        else:
                            # Values are in MB
                            memory_info['memory_total_mb'] = total
                            memory_info['memory_used_mb'] = used
                            memory_info['memory_free_mb'] = free
                            memory_info['memory_total'] = f"{total / 1024:.2f} GB"
                            memory_info['memory_used'] = f"{used / 1024:.2f} GB"
                            memory_info['memory_free'] = f"{free / 1024:.2f} GB"
                    except:
                        memory_info['memory_raw'] = line
            
            elif line.startswith('Swap:'):
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        total = int(parts[1])
                        used = int(parts[2])
                        
                        if total > 1000000:
                            memory_info['swap_total'] = f"{total / (1024**3):.2f} GB"
                            memory_info['swap_used'] = f"{used / (1024**3):.2f} GB"
                        else:
                            memory_info['swap_total'] = f"{total / 1024:.2f} GB"
                            memory_info['swap_used'] = f"{used / 1024:.2f} GB"
                    except:
                        pass
        
        return memory_info
    
    def _parse_disk_usage(self, output: str) -> list:
        """Parse disk usage from df command"""
        disk_usage = []
        lines = output.splitlines()
        
        if not lines:
            return disk_usage
        
        # Skip header
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 6:
                disk_usage.append({
                    'filesystem': parts[0],
                    'type': parts[1],
                    'size': parts[2],
                    'used': parts[3],
                    'available': parts[4],
                    'use_percent': parts[5],
                    'mount_point': parts[6] if len(parts) > 6 else parts[5]
                })
        
        return disk_usage
    
    def _parse_hardware_info(self, results: Dict) -> Dict[str, Any]:
        """Parse hardware information"""
        hardware = {}
        
        # PCI Devices
        if results.get('pci_devices', {}).get('success'):
            pci_lines = results['pci_devices']['stdout'].splitlines()
            hardware['pci_devices'] = []
            for line in pci_lines[:20]:  # Limit to first 20 devices
                if line.strip():
                    hardware['pci_devices'].append(line.strip())
        
        # USB Devices
        if results.get('usb_devices', {}).get('success'):
            usb_lines = results['usb_devices']['stdout'].splitlines()
            hardware['usb_devices'] = []
            for line in usb_lines[:20]:  # Limit to first 20 devices
                if line.strip():
                    hardware['usb_devices'].append(line.strip())
        
        # Network Interfaces
        if results.get('network_interfaces', {}).get('success'):
            net_output = results['network_interfaces']['stdout']
            if net_output.startswith('['):
                try:
                    hardware['network_interfaces'] = json.loads(net_output)
                except:
                    hardware['network_interfaces_raw'] = net_output
            else:
                hardware['network_interfaces_raw'] = net_output
        
        # Loaded Kernel Modules
        if results.get('loaded_modules', {}).get('success'):
            modules = []
            for line in results['loaded_modules']['stdout'].splitlines():
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 1:
                        modules.append(parts[0])
            hardware['kernel_modules'] = modules
        
        return hardware