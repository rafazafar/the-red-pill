import re
import json
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class ContainersModule:
    def __init__(self, discovery):
        self.discovery = discovery
    
    def collect(self) -> Dict[str, Any]:
        """Collect container and orchestration information"""
        logger.info("Collecting container information...")
        
        containers = {
            'docker': self._collect_docker_info(),
            'podman': self._collect_podman_info(),
            'kubernetes': self._collect_kubernetes_info(),
            'docker_compose': self._collect_compose_info(),
            'containerd': self._collect_containerd_info()
        }
        
        return containers
    
    def _collect_docker_info(self) -> Dict[str, Any]:
        """Collect Docker information"""
        docker_info = {}
        
        commands = {
            'version': 'docker version --format json 2>/dev/null || docker version 2>/dev/null',
            'info': 'docker info --format json 2>/dev/null || docker info 2>/dev/null',
            'containers': 'docker ps -a --format json 2>/dev/null || docker ps -a',
            'images': 'docker images --format json 2>/dev/null || docker images',
            'volumes': 'docker volume ls --format json 2>/dev/null || docker volume ls',
            'networks': 'docker network ls --format json 2>/dev/null || docker network ls',
            'compose_projects': 'docker compose ls 2>/dev/null || docker-compose ls 2>/dev/null'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # Docker version
        if results.get('version', {}).get('success'):
            output = results['version']['stdout']
            if output.startswith('{'):
                try:
                    docker_info['version'] = json.loads(output)
                except:
                    docker_info['version_raw'] = output[:500]
            else:
                docker_info['version_raw'] = output[:500]
        
        # Docker info
        if results.get('info', {}).get('success'):
            output = results['info']['stdout']
            if output.startswith('{'):
                try:
                    info = json.loads(output)
                    docker_info['info'] = {
                        'containers': info.get('Containers'),
                        'running': info.get('ContainersRunning'),
                        'paused': info.get('ContainersPaused'),
                        'stopped': info.get('ContainersStopped'),
                        'images': info.get('Images'),
                        'storage_driver': info.get('Driver'),
                        'docker_root': info.get('DockerRootDir')
                    }
                except:
                    pass
            else:
                # Parse text format
                for line in output.splitlines():
                    if 'Containers:' in line:
                        docker_info['total_containers'] = line.split(':')[1].strip()
                    elif 'Running:' in line:
                        docker_info['running_containers'] = line.split(':')[1].strip()
                    elif 'Images:' in line:
                        docker_info['total_images'] = line.split(':')[1].strip()
        
        # Containers
        if results.get('containers', {}).get('success'):
            containers = []
            output = results['containers']['stdout']
            
            if output.strip().startswith('['):
                try:
                    containers = json.loads(output)
                except:
                    pass
            else:
                # Parse table format
                lines = output.splitlines()[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 7:
                        containers.append({
                            'id': parts[0][:12],
                            'image': parts[1],
                            'command': parts[2],
                            'created': parts[3] + ' ' + parts[4],
                            'status': parts[5] if 'ago' not in parts[5] else parts[5] + ' ' + parts[6],
                            'name': parts[-1]
                        })
            
            docker_info['containers'] = containers[:50]  # Limit
        
        # Images
        if results.get('images', {}).get('success'):
            images = []
            output = results['images']['stdout']
            
            if output.strip().startswith('['):
                try:
                    images = json.loads(output)
                except:
                    pass
            else:
                # Parse table format
                lines = output.splitlines()[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 5:
                        images.append({
                            'repository': parts[0],
                            'tag': parts[1],
                            'id': parts[2][:12],
                            'created': parts[3] + ' ' + parts[4] if len(parts) > 5 else parts[3],
                            'size': parts[-1]
                        })
            
            docker_info['images'] = images[:50]  # Limit
        
        # Volumes
        if results.get('volumes', {}).get('success'):
            docker_info['volumes_count'] = results['volumes']['stdout'].count('\n') - 1  # Minus header
        
        # Networks
        if results.get('networks', {}).get('success'):
            networks = []
            for line in results['networks']['stdout'].splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    networks.append({
                        'id': parts[0][:12],
                        'name': parts[1],
                        'driver': parts[2]
                    })
            docker_info['networks'] = networks
        
        # Docker Compose projects
        if results.get('compose_projects', {}).get('success') and results['compose_projects']['stdout']:
            docker_info['compose_projects'] = results['compose_projects']['stdout'][:1000]
        
        return docker_info
    
    def _collect_podman_info(self) -> Dict[str, Any]:
        """Collect Podman information"""
        podman_info = {}
        
        commands = {
            'version': 'podman version 2>/dev/null',
            'info': 'podman info 2>/dev/null',
            'containers': 'podman ps -a 2>/dev/null',
            'images': 'podman images 2>/dev/null',
            'pods': 'podman pod ls 2>/dev/null'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        if results.get('version', {}).get('success') and 'podman' in results['version']['stdout'].lower():
            podman_info['installed'] = True
            podman_info['version'] = results['version']['stdout'][:500]
            
            # Containers
            if results.get('containers', {}).get('success'):
                container_count = len(results['containers']['stdout'].splitlines()) - 1
                podman_info['container_count'] = max(0, container_count)
            
            # Images
            if results.get('images', {}).get('success'):
                image_count = len(results['images']['stdout'].splitlines()) - 1
                podman_info['image_count'] = max(0, image_count)
            
            # Pods
            if results.get('pods', {}).get('success'):
                pod_count = len(results['pods']['stdout'].splitlines()) - 1
                podman_info['pod_count'] = max(0, pod_count)
        
        return podman_info
    
    def _collect_kubernetes_info(self) -> Dict[str, Any]:
        """Collect Kubernetes information"""
        k8s_info = {}
        
        commands = {
            'kubectl_version': 'kubectl version --short 2>/dev/null',
            'kubelet_version': 'kubelet --version 2>/dev/null',
            'kubeadm_version': 'kubeadm version 2>/dev/null',
            'nodes': 'kubectl get nodes 2>/dev/null',
            'pods': 'kubectl get pods --all-namespaces 2>/dev/null',
            'services': 'kubectl get services --all-namespaces 2>/dev/null',
            'deployments': 'kubectl get deployments --all-namespaces 2>/dev/null',
            'minikube': 'minikube status 2>/dev/null',
            'k3s': 'k3s --version 2>/dev/null',
            'microk8s': 'microk8s status 2>/dev/null'
        }
        
        results = self.discovery.execute_commands_parallel(commands, timeout=10)
        
        # Check for Kubernetes components
        if results.get('kubectl_version', {}).get('success'):
            k8s_info['kubectl'] = results['kubectl_version']['stdout'][:500]
        
        if results.get('kubelet_version', {}).get('success'):
            k8s_info['kubelet'] = results['kubelet_version']['stdout'].strip()
        
        if results.get('kubeadm_version', {}).get('success'):
            k8s_info['kubeadm'] = results['kubeadm_version']['stdout'][:200]
        
        # Cluster information (if kubectl is configured)
        if results.get('nodes', {}).get('success'):
            node_count = len(results['nodes']['stdout'].splitlines()) - 1
            k8s_info['node_count'] = max(0, node_count)
        
        if results.get('pods', {}).get('success'):
            pod_count = len(results['pods']['stdout'].splitlines()) - 1
            k8s_info['pod_count'] = max(0, pod_count)
        
        # Check for lightweight Kubernetes distributions
        if results.get('minikube', {}).get('success') and 'Running' in results['minikube']['stdout']:
            k8s_info['minikube'] = 'running'
        
        if results.get('k3s', {}).get('success'):
            k8s_info['k3s'] = results['k3s']['stdout'].strip()
        
        if results.get('microk8s', {}).get('success') and 'microk8s is running' in results['microk8s']['stdout']:
            k8s_info['microk8s'] = 'running'
        
        return k8s_info
    
    def _collect_compose_info(self) -> Dict[str, Any]:
        """Collect Docker Compose projects"""
        compose_info = {}
        
        # Find docker-compose files
        search_dirs = ['/var/www', '/srv', '/opt', '/home', '/root']
        find_cmd = f'find {" ".join(search_dirs)} -maxdepth 4 \\( -name "docker-compose.yml" -o -name "docker-compose.yaml" -o -name "compose.yml" -o -name "compose.yaml" \\) 2>/dev/null | head -50'
        
        result = self.discovery.execute_command(find_cmd, timeout=15)
        
        if result.get('success'):
            compose_files = []
            for path in result['stdout'].splitlines():
                if path:
                    compose_files.append(path)
            
            if compose_files:
                compose_info['compose_files'] = compose_files
                
                # Try to get project names from files
                projects = []
                for file_path in compose_files[:10]:  # Check first 10
                    check_cmd = f'grep -E "^(services:|version:)" {file_path} 2>/dev/null | head -2'
                    check_result = self.discovery.execute_command(check_cmd, timeout=5)
                    if check_result.get('success'):
                        projects.append({
                            'file': file_path,
                            'preview': check_result['stdout'][:100]
                        })
                
                if projects:
                    compose_info['projects'] = projects
        
        return compose_info
    
    def _collect_containerd_info(self) -> Dict[str, Any]:
        """Collect containerd information"""
        containerd_info = {}
        
        commands = {
            'version': 'containerd --version 2>/dev/null',
            'config': 'containerd config dump 2>/dev/null | head -50',
            'ctr_version': 'ctr version 2>/dev/null',
            'crictl_version': 'crictl version 2>/dev/null'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        if results.get('version', {}).get('success') and 'containerd' in results['version']['stdout']:
            containerd_info['version'] = results['version']['stdout'].strip()
        
        if results.get('ctr_version', {}).get('success'):
            containerd_info['ctr'] = results['ctr_version']['stdout'][:200]
        
        if results.get('crictl_version', {}).get('success'):
            containerd_info['crictl'] = results['crictl_version']['stdout'][:200]
        
        return containerd_info