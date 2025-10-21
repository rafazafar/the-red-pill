import json
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)


class BaseAnalyzer(ABC):
    """Base class for framework-specific application analyzers"""
    
    def __init__(self, discovery, app_path: str):
        self.discovery = discovery
        self.app_path = Path(app_path)
        self.analysis_results = {}
        
    @abstractmethod
    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive analysis of the application"""
        pass
    
    @property
    @abstractmethod
    def framework_name(self) -> str:
        """Return the framework name (e.g., 'Laravel', 'Node.js')"""
        pass
    
    def read_json_file(self, file_path: str, default: Dict = None) -> Dict[str, Any]:
        """Read and parse a JSON file"""
        if default is None:
            default = {}
            
        full_path = self.app_path / file_path
        cmd = f'cat "{full_path}" 2>/dev/null'
        result = self.discovery.execute_command(cmd, timeout=10)
        
        if result.get('success') and result['stdout']:
            try:
                return json.loads(result['stdout'])
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON file {full_path}: {e}")
                return default
        
        return default
    
    def read_file(self, file_path: str) -> str:
        """Read a text file and return its contents"""
        full_path = self.app_path / file_path
        cmd = f'cat "{full_path}" 2>/dev/null'
        result = self.discovery.execute_command(cmd, timeout=10)
        
        if result.get('success'):
            return result['stdout']
        
        return ""
    
    def file_exists(self, file_path: str) -> bool:
        """Check if a file exists in the application directory"""
        full_path = self.app_path / file_path
        cmd = f'test -f "{full_path}"'
        result = self.discovery.execute_command(cmd, timeout=5)
        
        return result.get('success', False)
    
    def directory_exists(self, dir_path: str) -> bool:
        """Check if a directory exists in the application directory"""
        full_path = self.app_path / dir_path
        cmd = f'test -d "{full_path}"'
        result = self.discovery.execute_command(cmd, timeout=5)
        
        return result.get('success', False)
    
    def find_files(self, pattern: str, max_depth: int = 4) -> List[str]:
        """Find files matching a pattern in the application directory"""
        cmd = f'find "{self.app_path}" -maxdepth {max_depth} -name "{pattern}" 2>/dev/null'
        result = self.discovery.execute_command(cmd, timeout=15)
        
        if result.get('success'):
            files = [line.strip() for line in result['stdout'].splitlines() if line.strip()]
            # Return paths relative to app_path
            return [str(Path(f).relative_to(self.app_path)) for f in files]
        
        return []
    
    def grep_files(self, pattern: str, file_pattern: str = "*", max_depth: int = 4) -> List[Dict[str, str]]:
        """Search for patterns in files"""
        cmd = f'find "{self.app_path}" -maxdepth {max_depth} -name "{file_pattern}" -type f -exec grep -l "{pattern}" {{}} \\; 2>/dev/null'
        result = self.discovery.execute_command(cmd, timeout=15)
        
        matches = []
        if result.get('success'):
            for file_path in result['stdout'].splitlines():
                if file_path:
                    rel_path = str(Path(file_path).relative_to(self.app_path))
                    matches.append({
                        'file': rel_path,
                        'pattern': pattern
                    })
        
        return matches
    
    def extract_env_vars(self, content: str) -> List[str]:
        """Extract environment variable names from content"""
        # Match env('VAR_NAME'), getenv('VAR_NAME'), $_ENV['VAR_NAME'], process.env.VAR_NAME
        patterns = [
            r'env\([\'"]([A-Z_][A-Z0-9_]*)[\'"]',
            r'getenv\([\'"]([A-Z_][A-Z0-9_]*)[\'"]',
            r'\$_ENV\[[\'"]([A-Z_][A-Z0-9_]*)[\'"]',
            r'process\.env\.([A-Z_][A-Z0-9_]*)',
            r'\$([A-Z_][A-Z0-9_]*)',  # Direct variable references
        ]
        
        env_vars = set()
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            env_vars.update(matches)
        
        return sorted(list(env_vars))
    
    def parse_version_constraint(self, constraint: str) -> Dict[str, str]:
        """Parse version constraints like '^8.1', '>=10.0', '~1.2.3'"""
        constraint = constraint.strip()
        
        # Remove 'v' prefix if present
        if constraint.startswith('v'):
            constraint = constraint[1:]
        
        version_info = {'constraint': constraint}
        
        if constraint.startswith('^'):
            version_info['type'] = 'compatible'
            version_info['min_version'] = constraint[1:]
        elif constraint.startswith('~'):
            version_info['type'] = 'approximate'
            version_info['min_version'] = constraint[1:]
        elif constraint.startswith('>='):
            version_info['type'] = 'minimum'
            version_info['min_version'] = constraint[2:]
        elif constraint.startswith('>'):
            version_info['type'] = 'greater_than'
            version_info['min_version'] = constraint[1:]
        elif constraint.startswith('<='):
            version_info['type'] = 'maximum'
            version_info['max_version'] = constraint[2:]
        elif constraint.startswith('<'):
            version_info['type'] = 'less_than'
            version_info['max_version'] = constraint[1:]
        elif constraint.startswith('='):
            version_info['type'] = 'exact'
            version_info['exact_version'] = constraint[1:]
        else:
            version_info['type'] = 'exact'
            version_info['exact_version'] = constraint
        
        return version_info
    
    def get_file_permissions(self, file_path: str) -> Optional[str]:
        """Get file permissions for a file or directory"""
        full_path = self.app_path / file_path
        cmd = f'stat -c "%a" "{full_path}" 2>/dev/null || stat -f "%OLp" "{full_path}" 2>/dev/null'
        result = self.discovery.execute_command(cmd, timeout=5)
        
        if result.get('success') and result['stdout'].strip():
            return result['stdout'].strip()
        
        return None
    
    def get_directory_size(self, dir_path: str) -> Optional[str]:
        """Get directory size in human readable format"""
        full_path = self.app_path / dir_path
        cmd = f'du -sh "{full_path}" 2>/dev/null | cut -f1'
        result = self.discovery.execute_command(cmd, timeout=10)
        
        if result.get('success') and result['stdout'].strip():
            return result['stdout'].strip()
        
        return None
    
    def check_command_available(self, command: str) -> bool:
        """Check if a command is available in the system"""
        cmd = f'command -v {command} >/dev/null 2>&1'
        result = self.discovery.execute_command(cmd, timeout=5)
        
        return result.get('success', False)
    
    def get_command_version(self, command: str, version_flag: str = '--version') -> Optional[str]:
        """Get version of a command"""
        cmd = f'{command} {version_flag} 2>/dev/null | head -1'
        result = self.discovery.execute_command(cmd, timeout=10)
        
        if result.get('success') and result['stdout'].strip():
            return result['stdout'].strip()
        
        return None
    
    def parse_requirements_from_comments(self, content: str) -> List[str]:
        """Extract requirements from code comments"""
        requirements = []
        
        # Look for TODO, FIXME, REQUIRES comments
        comment_patterns = [
            r'#\s*(TODO|FIXME|REQUIRES?):?\s*(.+)',
            r'//\s*(TODO|FIXME|REQUIRES?):?\s*(.+)',
            r'/\*\s*(TODO|FIXME|REQUIRES?):?\s*(.+?)\*/',
        ]
        
        for pattern in comment_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                if len(match) >= 2:
                    requirements.append(f"{match[0]}: {match[1].strip()}")
        
        return requirements
    
    def categorize_dependencies(self, dependencies: Dict[str, str]) -> Dict[str, List[Dict]]:
        """Categorize dependencies by type"""
        categories = {
            'databases': [],
            'cache': [],
            'queue': [],
            'http_clients': [],
            'authentication': [],
            'payment': [],
            'cloud_services': [],
            'testing': [],
            'development': [],
            'build_tools': [],
            'other': []
        }
        
        # Define patterns for categorization
        patterns = {
            'databases': ['mysql', 'postgres', 'sqlite', 'mongodb', 'redis', 'doctrine', 'eloquent', 'sequelize', 'mongoose', 'prisma'],
            'cache': ['redis', 'memcache', 'cache'],
            'queue': ['queue', 'job', 'bull', 'bee-queue', 'kue'],
            'http_clients': ['axios', 'guzzle', 'request', 'fetch', 'curl'],
            'authentication': ['auth', 'passport', 'jwt', 'oauth', 'sanctum'],
            'payment': ['stripe', 'paypal', 'square', 'braintree'],
            'cloud_services': ['aws', 'gcp', 'azure', 's3', 'ses', 'sqs'],
            'testing': ['test', 'jest', 'mocha', 'phpunit', 'pest'],
            'development': ['dev', 'debug', 'hot', 'watch'],
            'build_tools': ['webpack', 'vite', 'rollup', 'parcel', 'esbuild', 'babel']
        }
        
        for dep_name, version in dependencies.items():
            categorized = False
            
            for category, keywords in patterns.items():
                if any(keyword in dep_name.lower() for keyword in keywords):
                    categories[category].append({
                        'name': dep_name,
                        'version': version
                    })
                    categorized = True
                    break
            
            if not categorized:
                categories['other'].append({
                    'name': dep_name,
                    'version': version
                })
        
        # Remove empty categories
        return {k: v for k, v in categories.items() if v}
    
    def generate_deployment_checklist(self) -> List[str]:
        """Generate a basic deployment checklist - to be overridden by specific analyzers"""
        return [
            "Review framework-specific requirements",
            "Set up environment variables",
            "Configure database connections", 
            "Set up file permissions",
            "Install and configure web server"
        ]
    
    def generate_security_warnings(self) -> List[str]:
        """Generate security warnings - to be overridden by specific analyzers"""
        warnings = []
        
        # Check for common security issues
        if self.file_exists('.env') and self.get_file_permissions('.env') not in ['600', '644']:
            warnings.append("Environment file (.env) has overly permissive permissions")
        
        return warnings