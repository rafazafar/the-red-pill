import re
import json
from typing import Dict, Any, List
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Import specialized analyzers
try:
    from .app_analyzers.laravel_analyzer import LaravelAnalyzer
    from .app_analyzers.nodejs_analyzer import NodeJSAnalyzer
    ANALYZERS_AVAILABLE = True
except ImportError:
    ANALYZERS_AVAILABLE = False
    logger.warning("Specialized analyzers not available")


class ApplicationsModule:
    def __init__(self, discovery):
        self.discovery = discovery
        self.search_dirs = ['/var/www', '/srv', '/opt', '/usr/local', '/home', '/app', '/data']
    
    def collect(self) -> Dict[str, Any]:
        """Collect comprehensive application information"""
        logger.info("Collecting application information...")
        
        applications = {
            'php': self._detect_php_applications(),
            'nodejs': self._detect_nodejs_applications(),
            'python': self._detect_python_applications(),
            'ruby': self._detect_ruby_applications(),
            'java': self._detect_java_applications(),
            'dotnet': self._detect_dotnet_applications(),
            'golang': self._detect_golang_applications(),
            'rust': self._detect_rust_applications(),
            'web_frameworks': self._detect_web_frameworks(),
            'static_sites': self._detect_static_sites()
        }
        
        # Collect application manifests and configurations
        applications['manifests'] = self._collect_manifests()
        applications['process_info'] = self._collect_process_info()
        
        return applications
    
    def _detect_php_applications(self) -> Dict[str, Any]:
        """Detect PHP applications and frameworks"""
        php_info = {}
        
        commands = {
            'php_version': 'php -v 2>/dev/null | head -1 || true',
            'php_modules': 'php -m 2>/dev/null || true',
            'php_ini': 'php --ini 2>/dev/null || true',
            'composer_version': 'composer --version 2>/dev/null || true',
            'php_fpm_status': 'systemctl status php*-fpm 2>/dev/null || service php*-fpm status 2>/dev/null || true',
            'find_php_apps': f'find {" ".join(self.search_dirs)} -maxdepth 4 -path "*/vendor" -prune -o -path "*/node_modules" -prune -o -type f \\( -name "index.php" -o -name "composer.json" -o -name "artisan" -o -name "wp-config.php" \\) -print 2>/dev/null | head -100 || true'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # PHP Version
        if results.get('php_version', {}).get('success'):
            version_line = results['php_version']['stdout'].strip()
            if version_line:
                php_info['version'] = version_line
        
        # PHP Modules
        if results.get('php_modules', {}).get('success'):
            modules = [line.strip() for line in results['php_modules']['stdout'].splitlines() if line.strip()]
            php_info['modules'] = modules
        
        # PHP Configuration
        if results.get('php_ini', {}).get('success'):
            php_info['configuration'] = results['php_ini']['stdout'].strip()
        
        # Composer
        if results.get('composer_version', {}).get('success') and 'Composer' in results['composer_version']['stdout']:
            php_info['composer'] = results['composer_version']['stdout'].strip()
        
        # PHP-FPM
        if results.get('php_fpm_status', {}).get('success'):
            if 'active (running)' in results['php_fpm_status']['stdout']:
                php_info['php_fpm'] = 'running'
            elif 'inactive' in results['php_fpm_status']['stdout']:
                php_info['php_fpm'] = 'inactive'
        
        # Detect PHP Applications
        if results.get('find_php_apps', {}).get('success'):
            apps = []
            frameworks = {
                'laravel': [],
                'symfony': [],
                'wordpress': [],
                'drupal': [],
                'magento': [],
                'codeigniter': [],
                'yii': [],
                'cakephp': []
            }
            
            for path in results['find_php_apps']['stdout'].splitlines():
                if not path:
                    continue
                
                # Check for specific frameworks
                if 'artisan' in path:
                    frameworks['laravel'].append(str(Path(path).parent))
                elif 'wp-config.php' in path or 'wp-content' in path:
                    frameworks['wordpress'].append(str(Path(path).parent))
                elif 'composer.json' in path:
                    # Read composer.json to identify framework
                    check_cmd = f'cat {path} 2>/dev/null | head -50'
                    check_result = self.discovery.execute_command(check_cmd, timeout=5)
                    if check_result.get('success'):
                        content = check_result['stdout']
                        if 'laravel/framework' in content:
                            frameworks['laravel'].append(str(Path(path).parent))
                        elif 'symfony/symfony' in content or 'symfony/framework-bundle' in content:
                            frameworks['symfony'].append(str(Path(path).parent))
                        elif 'drupal/core' in content:
                            frameworks['drupal'].append(str(Path(path).parent))
                        elif 'magento/framework' in content:
                            frameworks['magento'].append(str(Path(path).parent))
                        elif 'codeigniter/framework' in content:
                            frameworks['codeigniter'].append(str(Path(path).parent))
                        elif 'yiisoft/yii' in content:
                            frameworks['yii'].append(str(Path(path).parent))
                        elif 'cakephp/cakephp' in content:
                            frameworks['cakephp'].append(str(Path(path).parent))
                        else:
                            apps.append(str(Path(path).parent))
                elif 'index.php' in path:
                    parent_dir = str(Path(path).parent)
                    # Check for framework indicators
                    framework_checks = {
                        'drupal': 'find {} -maxdepth 2 -name "drupal.php" 2>/dev/null',
                        'magento': 'find {} -maxdepth 2 -name "mage.php" 2>/dev/null',
                        'codeigniter': 'find {} -maxdepth 2 -path "*/system/core/CodeIgniter.php" 2>/dev/null'
                    }
                    
                    identified = False
                    for fw_name, fw_cmd in framework_checks.items():
                        check_result = self.discovery.execute_command(fw_cmd.format(parent_dir), timeout=5)
                        if check_result.get('success') and check_result['stdout'].strip():
                            frameworks[fw_name].append(parent_dir)
                            identified = True
                            break
                    
                    if not identified and parent_dir not in apps:
                        apps.append(parent_dir)
            
            php_info['applications'] = apps
            php_info['frameworks'] = {k: list(set(v)) for k, v in frameworks.items() if v}
            
            # Run specialized analysis for Laravel applications
            if ANALYZERS_AVAILABLE and frameworks.get('laravel'):
                laravel_analysis = {}
                # Deduplicate Laravel paths
                unique_laravel_paths = list(set(frameworks['laravel']))
                for laravel_path in unique_laravel_paths:
                    try:
                        analyzer = LaravelAnalyzer(self.discovery, laravel_path)
                        analysis_result = analyzer.analyze()
                        laravel_analysis[laravel_path] = analysis_result
                        logger.info(f"Completed Laravel analysis for {laravel_path}")
                    except Exception as e:
                        logger.error(f"Failed to analyze Laravel app at {laravel_path}: {e}")
                        laravel_analysis[laravel_path] = {'error': str(e)}

                if laravel_analysis:
                    php_info['laravel_detailed_analysis'] = laravel_analysis
        
        return php_info
    
    def _detect_nodejs_applications(self) -> Dict[str, Any]:
        """Detect Node.js applications"""
        node_info = {}
        
        commands = {
            'node_version': 'node -v 2>/dev/null || true',
            'npm_version': 'npm -v 2>/dev/null || true',
            'yarn_version': 'yarn -v 2>/dev/null || true',
            'pnpm_version': 'pnpm -v 2>/dev/null || true',
            'bun_version': 'bun -v 2>/dev/null || true',
            'pm2_list': 'pm2 list 2>/dev/null || pm2 jlist 2>/dev/null || true',
            'find_node_apps': f'find {" ".join(self.search_dirs)} -maxdepth 4 -path "*/node_modules" -prune -o -name "package.json" -print 2>/dev/null | head -100 || true',
            'node_processes': 'ps aux | grep -E "(node|bun|deno)" | grep -v grep || true'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # Node.js Version
        if results.get('node_version', {}).get('success'):
            node_info['node_version'] = results['node_version']['stdout'].strip()
        
        # Package Managers
        if results.get('npm_version', {}).get('success'):
            node_info['npm_version'] = results['npm_version']['stdout'].strip()
        if results.get('yarn_version', {}).get('success') and results['yarn_version']['stdout'].strip():
            node_info['yarn_version'] = results['yarn_version']['stdout'].strip()
        if results.get('pnpm_version', {}).get('success') and results['pnpm_version']['stdout'].strip():
            node_info['pnpm_version'] = results['pnpm_version']['stdout'].strip()
        if results.get('bun_version', {}).get('success') and results['bun_version']['stdout'].strip():
            node_info['bun_version'] = results['bun_version']['stdout'].strip()
        
        # PM2 Applications
        if results.get('pm2_list', {}).get('success'):
            pm2_output = results['pm2_list']['stdout']
            if pm2_output.startswith('['):  # JSON format
                try:
                    node_info['pm2_apps'] = json.loads(pm2_output)
                except:
                    node_info['pm2_raw'] = pm2_output
            else:
                node_info['pm2_raw'] = pm2_output
        
        # Find Node.js Applications
        if results.get('find_node_apps', {}).get('success'):
            apps = []
            frameworks = {
                'express': [],
                'nextjs': [],
                'nuxtjs': [],
                'react': [],
                'vue': [],
                'angular': [],
                'nestjs': [],
                'gatsby': [],
                'svelte': []
            }
            
            for path in results['find_node_apps']['stdout'].splitlines():
                if not path:
                    continue
                
                # Read package.json to identify framework
                check_cmd = f'cat {path} 2>/dev/null | head -100'
                check_result = self.discovery.execute_command(check_cmd, timeout=5)
                if check_result.get('success'):
                    try:
                        package_json = json.loads(check_result['stdout'])
                        dependencies = {**package_json.get('dependencies', {}), **package_json.get('devDependencies', {})}
                        
                        app_dir = str(Path(path).parent)
                        app_info = {
                            'path': app_dir,
                            'name': package_json.get('name', 'unknown'),
                            'version': package_json.get('version', 'unknown')
                        }
                        
                        # Identify frameworks
                        if 'express' in dependencies:
                            frameworks['express'].append(app_info)
                        if 'next' in dependencies:
                            frameworks['nextjs'].append(app_info)
                        if 'nuxt' in dependencies or 'nuxt3' in dependencies:
                            frameworks['nuxtjs'].append(app_info)
                        if 'react' in dependencies:
                            frameworks['react'].append(app_info)
                        if 'vue' in dependencies:
                            frameworks['vue'].append(app_info)
                        if '@angular/core' in dependencies:
                            frameworks['angular'].append(app_info)
                        if '@nestjs/core' in dependencies:
                            frameworks['nestjs'].append(app_info)
                        if 'gatsby' in dependencies:
                            frameworks['gatsby'].append(app_info)
                        if 'svelte' in dependencies:
                            frameworks['svelte'].append(app_info)
                        
                        # Check for specific app types
                        if package_json.get('scripts', {}).get('start'):
                            app_info['has_start_script'] = True
                        
                        apps.append(app_info)
                    except:
                        apps.append({'path': str(Path(path).parent), 'parse_error': True})
            
            node_info['applications'] = apps
            node_info['frameworks'] = {k: v for k, v in frameworks.items() if v}
            
            # Run specialized analysis for Node.js applications
            if ANALYZERS_AVAILABLE and apps:
                nodejs_analysis = {}

                # Deduplicate and filter Node.js apps
                unique_app_paths = set()
                for app_info in apps:
                    app_path = app_info.get('path') if isinstance(app_info, dict) else app_info
                    if app_path and 'node_modules' not in app_path:  # Extra safety check
                        unique_app_paths.add(app_path)

                # Analyze each unique Node.js application
                for app_path in unique_app_paths:
                    try:
                        analyzer = NodeJSAnalyzer(self.discovery, app_path)
                        analysis_result = analyzer.analyze()
                        nodejs_analysis[app_path] = analysis_result
                        logger.info(f"Completed Node.js analysis for {app_path}")
                    except Exception as e:
                        logger.error(f"Failed to analyze Node.js app at {app_path}: {e}")
                        nodejs_analysis[app_path] = {'error': str(e)}

                if nodejs_analysis:
                    node_info['nodejs_detailed_analysis'] = nodejs_analysis
        
        # Running Node processes
        if results.get('node_processes', {}).get('success'):
            processes = []
            for line in results['node_processes']['stdout'].splitlines():
                if line.strip():
                    parts = line.split(None, 10)
                    if len(parts) > 10:
                        processes.append({
                            'user': parts[0],
                            'pid': parts[1],
                            'command': parts[10]
                        })
            node_info['running_processes'] = processes[:10]  # Limit to 10
        
        return node_info
    
    def _detect_python_applications(self) -> Dict[str, Any]:
        """Detect Python applications"""
        python_info = {}
        
        commands = {
            'python_version': 'python --version 2>&1 || python3 --version 2>&1 || true',
            'pip_version': 'pip --version 2>/dev/null || pip3 --version 2>/dev/null || true',
            'pipenv_version': 'pipenv --version 2>/dev/null || true',
            'poetry_version': 'poetry --version 2>/dev/null || true',
            'conda_version': 'conda --version 2>/dev/null || true',
            'find_python_apps': f'find {" ".join(self.search_dirs)} -maxdepth 4 \\( -name "requirements.txt" -o -name "Pipfile" -o -name "pyproject.toml" -o -name "setup.py" -o -name "manage.py" -o -name "app.py" -o -name "main.py" \\) 2>/dev/null | head -100 || true',
            'python_processes': 'ps aux | grep -E "(python|gunicorn|uwsgi|celery|django|flask)" | grep -v grep || true',
            'virtualenvs': f'find {" ".join(self.search_dirs)} -maxdepth 5 -name "pyvenv.cfg" 2>/dev/null | head -50 || true'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # Python Version
        if results.get('python_version', {}).get('success'):
            python_info['version'] = results['python_version']['stdout'].strip()
        
        # Package Managers
        if results.get('pip_version', {}).get('success'):
            python_info['pip_version'] = results['pip_version']['stdout'].strip()
        if results.get('pipenv_version', {}).get('success') and 'pipenv' in results['pipenv_version']['stdout'].lower():
            python_info['pipenv_version'] = results['pipenv_version']['stdout'].strip()
        if results.get('poetry_version', {}).get('success') and 'poetry' in results['poetry_version']['stdout'].lower():
            python_info['poetry_version'] = results['poetry_version']['stdout'].strip()
        if results.get('conda_version', {}).get('success') and 'conda' in results['conda_version']['stdout'].lower():
            python_info['conda_version'] = results['conda_version']['stdout'].strip()
        
        # Find Python Applications
        if results.get('find_python_apps', {}).get('success'):
            apps = []
            frameworks = {
                'django': [],
                'flask': [],
                'fastapi': [],
                'pyramid': [],
                'bottle': [],
                'tornado': [],
                'aiohttp': [],
                'jupyter': []
            }
            
            for path in results['find_python_apps']['stdout'].splitlines():
                if not path:
                    continue
                
                app_dir = str(Path(path).parent)
                filename = Path(path).name
                
                # Django detection
                if filename == 'manage.py':
                    frameworks['django'].append(app_dir)
                    continue
                
                # Check requirements files
                if filename in ['requirements.txt', 'Pipfile']:
                    check_cmd = f'cat {path} 2>/dev/null | head -100'
                    check_result = self.discovery.execute_command(check_cmd, timeout=5)
                    if check_result.get('success'):
                        content = check_result['stdout'].lower()
                        
                        if 'django' in content:
                            frameworks['django'].append(app_dir)
                        if 'flask' in content:
                            frameworks['flask'].append(app_dir)
                        if 'fastapi' in content:
                            frameworks['fastapi'].append(app_dir)
                        if 'pyramid' in content:
                            frameworks['pyramid'].append(app_dir)
                        if 'bottle' in content:
                            frameworks['bottle'].append(app_dir)
                        if 'tornado' in content:
                            frameworks['tornado'].append(app_dir)
                        if 'aiohttp' in content:
                            frameworks['aiohttp'].append(app_dir)
                        if 'jupyter' in content or 'notebook' in content:
                            frameworks['jupyter'].append(app_dir)
                
                # Check app.py/main.py for framework imports
                if filename in ['app.py', 'main.py']:
                    check_cmd = f'head -20 {path} 2>/dev/null'
                    check_result = self.discovery.execute_command(check_cmd, timeout=5)
                    if check_result.get('success'):
                        content = check_result['stdout']
                        
                        if 'from flask' in content or 'import flask' in content:
                            frameworks['flask'].append(app_dir)
                        elif 'from fastapi' in content or 'import fastapi' in content:
                            frameworks['fastapi'].append(app_dir)
                        elif 'from django' in content or 'import django' in content:
                            frameworks['django'].append(app_dir)
                        elif 'from pyramid' in content or 'import pyramid' in content:
                            frameworks['pyramid'].append(app_dir)
                        elif 'from bottle' in content or 'import bottle' in content:
                            frameworks['bottle'].append(app_dir)
                        elif 'from tornado' in content or 'import tornado' in content:
                            frameworks['tornado'].append(app_dir)
                        elif 'from aiohttp' in content or 'import aiohttp' in content:
                            frameworks['aiohttp'].append(app_dir)
                        else:
                            apps.append(app_dir)
                
                # pyproject.toml
                if filename == 'pyproject.toml':
                    apps.append(app_dir)
            
            python_info['applications'] = list(set(apps))
            python_info['frameworks'] = {k: list(set(v)) for k, v in frameworks.items() if v}
        
        # Virtual Environments
        if results.get('virtualenvs', {}).get('success'):
            venvs = []
            for path in results['virtualenvs']['stdout'].splitlines():
                if path:
                    venv_dir = str(Path(path).parent)
                    venvs.append(venv_dir)
            python_info['virtual_environments'] = venvs
        
        # Running Python processes
        if results.get('python_processes', {}).get('success'):
            processes = []
            for line in results['python_processes']['stdout'].splitlines():
                if line.strip():
                    parts = line.split(None, 10)
                    if len(parts) > 10:
                        processes.append({
                            'user': parts[0],
                            'pid': parts[1],
                            'command': parts[10][:200]  # Limit command length
                        })
            python_info['running_processes'] = processes[:10]  # Limit to 10
        
        return python_info
    
    def _detect_ruby_applications(self) -> Dict[str, Any]:
        """Detect Ruby applications"""
        ruby_info = {}
        
        commands = {
            'ruby_version': 'ruby -v 2>/dev/null || true',
            'gem_version': 'gem -v 2>/dev/null || true',
            'bundler_version': 'bundle -v 2>/dev/null || true',
            'rails_version': 'rails -v 2>/dev/null || true',
            'find_ruby_apps': f'find {" ".join(self.search_dirs)} -maxdepth 4 \\( -name "Gemfile" -o -name "config.ru" -o -name "Rakefile" \\) 2>/dev/null | head -100 || true',
            'ruby_processes': 'ps aux | grep -E "(ruby|rails|puma|unicorn|sidekiq)" | grep -v grep || true'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        if results.get('ruby_version', {}).get('success'):
            ruby_info['version'] = results['ruby_version']['stdout'].strip()
        
        if results.get('gem_version', {}).get('success'):
            ruby_info['gem_version'] = results['gem_version']['stdout'].strip()
        
        if results.get('bundler_version', {}).get('success') and 'Bundler' in results['bundler_version']['stdout']:
            ruby_info['bundler_version'] = results['bundler_version']['stdout'].strip()
        
        if results.get('rails_version', {}).get('success') and 'Rails' in results['rails_version']['stdout']:
            ruby_info['rails_version'] = results['rails_version']['stdout'].strip()
        
        # Find Ruby Applications
        if results.get('find_ruby_apps', {}).get('success'):
            apps = []
            rails_apps = []
            sinatra_apps = []
            
            for path in results['find_ruby_apps']['stdout'].splitlines():
                if not path:
                    continue
                
                app_dir = str(Path(path).parent)
                filename = Path(path).name
                
                if filename == 'Gemfile':
                    # Check for Rails or Sinatra
                    check_cmd = f'cat {path} 2>/dev/null | head -50'
                    check_result = self.discovery.execute_command(check_cmd, timeout=5)
                    if check_result.get('success'):
                        content = check_result['stdout']
                        if 'rails' in content.lower():
                            rails_apps.append(app_dir)
                        elif 'sinatra' in content.lower():
                            sinatra_apps.append(app_dir)
                        else:
                            apps.append(app_dir)
                elif filename == 'config.ru':
                    # Rack application
                    apps.append(app_dir)
            
            ruby_info['applications'] = list(set(apps))
            if rails_apps:
                ruby_info['rails_applications'] = list(set(rails_apps))
            if sinatra_apps:
                ruby_info['sinatra_applications'] = list(set(sinatra_apps))
        
        # Running Ruby processes
        if results.get('ruby_processes', {}).get('success'):
            processes = []
            for line in results['ruby_processes']['stdout'].splitlines():
                if line.strip():
                    parts = line.split(None, 10)
                    if len(parts) > 10:
                        processes.append({
                            'user': parts[0],
                            'pid': parts[1],
                            'command': parts[10][:200]
                        })
            ruby_info['running_processes'] = processes[:10]
        
        return ruby_info
    
    def _detect_java_applications(self) -> Dict[str, Any]:
        """Detect Java applications"""
        java_info = {}
        
        commands = {
            'java_version': 'java -version 2>&1 | head -3 || true',
            'maven_version': 'mvn -v 2>/dev/null | head -1 || true',
            'gradle_version': 'gradle -v 2>/dev/null | head -2 || true',
            'find_java_apps': f'find {" ".join(self.search_dirs)} -maxdepth 4 \\( -name "pom.xml" -o -name "build.gradle" -o -name "build.gradle.kts" -o -name "*.war" -o -name "*.jar" \\) 2>/dev/null | head -100 || true',
            'java_processes': 'ps aux | grep java | grep -v grep || true',
            'tomcat_check': 'ps aux | grep -E "(tomcat|catalina)" | grep -v grep || true',
            'jboss_check': 'ps aux | grep -E "(jboss|wildfly)" | grep -v grep || true'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        if results.get('java_version', {}).get('success'):
            java_info['version'] = results['java_version']['stdout'].strip()
        
        if results.get('maven_version', {}).get('success') and 'Maven' in results['maven_version']['stdout']:
            java_info['maven_version'] = results['maven_version']['stdout'].strip()
        
        if results.get('gradle_version', {}).get('success') and 'Gradle' in results['gradle_version']['stdout']:
            java_info['gradle_version'] = results['gradle_version']['stdout'].strip()
        
        # Find Java Applications
        if results.get('find_java_apps', {}).get('success'):
            maven_projects = []
            gradle_projects = []
            war_files = []
            jar_files = []
            
            for path in results['find_java_apps']['stdout'].splitlines():
                if not path:
                    continue
                
                if path.endswith('pom.xml'):
                    maven_projects.append(str(Path(path).parent))
                elif 'build.gradle' in path:
                    gradle_projects.append(str(Path(path).parent))
                elif path.endswith('.war'):
                    war_files.append(path)
                elif path.endswith('.jar'):
                    jar_files.append(path)
            
            if maven_projects:
                java_info['maven_projects'] = list(set(maven_projects))
            if gradle_projects:
                java_info['gradle_projects'] = list(set(gradle_projects))
            if war_files:
                java_info['war_deployments'] = war_files[:20]  # Limit
            if jar_files:
                java_info['jar_files'] = jar_files[:20]  # Limit
        
        # Application Servers
        if results.get('tomcat_check', {}).get('success') and results['tomcat_check']['stdout']:
            java_info['tomcat'] = 'running'
        
        if results.get('jboss_check', {}).get('success') and results['jboss_check']['stdout']:
            java_info['jboss_wildfly'] = 'running'
        
        # Running Java processes
        if results.get('java_processes', {}).get('success'):
            processes = []
            for line in results['java_processes']['stdout'].splitlines():
                if line.strip():
                    parts = line.split(None, 10)
                    if len(parts) > 10:
                        # Extract main class or jar
                        command = parts[10]
                        main_class = 'unknown'
                        if '-jar' in command:
                            jar_match = re.search(r'-jar\s+(\S+)', command)
                            if jar_match:
                                main_class = jar_match.group(1)
                        elif 'org.' in command or 'com.' in command:
                            class_match = re.search(r'((?:org|com)\.\S+)', command)
                            if class_match:
                                main_class = class_match.group(1).split()[0]
                        
                        processes.append({
                            'user': parts[0],
                            'pid': parts[1],
                            'main': main_class
                        })
            java_info['running_processes'] = processes[:10]
        
        return java_info
    
    def _detect_dotnet_applications(self) -> Dict[str, Any]:
        """Detect .NET applications"""
        dotnet_info = {}
        
        commands = {
            'dotnet_version': 'dotnet --version 2>/dev/null || true',
            'dotnet_info': 'dotnet --info 2>/dev/null || true',
            'find_dotnet_apps': f'find {" ".join(self.search_dirs)} -maxdepth 4 \\( -name "*.csproj" -o -name "*.fsproj" -o -name "*.vbproj" -o -name "project.json" \\) 2>/dev/null | head -100 || true',
            'dotnet_processes': 'ps aux | grep dotnet | grep -v grep || true'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        if results.get('dotnet_version', {}).get('success') and results['dotnet_version']['stdout'].strip():
            dotnet_info['version'] = results['dotnet_version']['stdout'].strip()
        
        if results.get('dotnet_info', {}).get('success'):
            dotnet_info['info'] = results['dotnet_info']['stdout'][:1000]  # Limit size
        
        # Find .NET Applications
        if results.get('find_dotnet_apps', {}).get('success'):
            projects = []
            for path in results['find_dotnet_apps']['stdout'].splitlines():
                if path:
                    projects.append({
                        'path': str(Path(path).parent),
                        'project_file': Path(path).name
                    })
            dotnet_info['projects'] = projects
        
        # Running .NET processes
        if results.get('dotnet_processes', {}).get('success'):
            processes = []
            for line in results['dotnet_processes']['stdout'].splitlines():
                if line.strip():
                    parts = line.split(None, 10)
                    if len(parts) > 10:
                        processes.append({
                            'user': parts[0],
                            'pid': parts[1],
                            'command': parts[10][:200]
                        })
            dotnet_info['running_processes'] = processes[:10]
        
        return dotnet_info
    
    def _detect_golang_applications(self) -> Dict[str, Any]:
        """Detect Go applications"""
        go_info = {}
        
        commands = {
            'go_version': 'go version 2>/dev/null || true',
            'go_env': 'go env GOPATH GOROOT 2>/dev/null || true',
            'find_go_apps': f'find {" ".join(self.search_dirs)} -maxdepth 4 \\( -name "go.mod" -o -name "go.sum" \\) 2>/dev/null | head -100 || true'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        if results.get('go_version', {}).get('success') and 'go version' in results['go_version']['stdout']:
            go_info['version'] = results['go_version']['stdout'].strip()
        
        if results.get('go_env', {}).get('success'):
            go_info['environment'] = results['go_env']['stdout'].strip()
        
        # Find Go Applications
        if results.get('find_go_apps', {}).get('success'):
            apps = []
            for path in results['find_go_apps']['stdout'].splitlines():
                if path and 'go.mod' in path:
                    apps.append(str(Path(path).parent))
            go_info['applications'] = list(set(apps))
        
        return go_info
    
    def _detect_rust_applications(self) -> Dict[str, Any]:
        """Detect Rust applications"""
        rust_info = {}
        
        commands = {
            'rust_version': 'rustc --version 2>/dev/null || true',
            'cargo_version': 'cargo --version 2>/dev/null || true',
            'find_rust_apps': f'find {" ".join(self.search_dirs)} -maxdepth 4 -name "Cargo.toml" 2>/dev/null | head -100 || true'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        if results.get('rust_version', {}).get('success') and 'rustc' in results['rust_version']['stdout']:
            rust_info['rustc_version'] = results['rust_version']['stdout'].strip()
        
        if results.get('cargo_version', {}).get('success') and 'cargo' in results['cargo_version']['stdout']:
            rust_info['cargo_version'] = results['cargo_version']['stdout'].strip()
        
        # Find Rust Applications
        if results.get('find_rust_apps', {}).get('success'):
            apps = []
            for path in results['find_rust_apps']['stdout'].splitlines():
                if path:
                    apps.append(str(Path(path).parent))
            rust_info['applications'] = apps
        
        return rust_info
    
    def _detect_web_frameworks(self) -> Dict[str, Any]:
        """Detect various web frameworks and CMSs"""
        frameworks = {}
        
        # Check for common web frameworks and CMSs
        cms_checks = {
            'wordpress': f'find {" ".join(self.search_dirs)} -maxdepth 4 -name "wp-config.php" 2>/dev/null | head -20',
            'drupal': f'find {" ".join(self.search_dirs)} -maxdepth 4 -path "*/sites/default/settings.php" 2>/dev/null | head -20',
            'joomla': f'find {" ".join(self.search_dirs)} -maxdepth 4 -name "configuration.php" -path "*/joomla/*" 2>/dev/null | head -20',
            'magento': f'find {" ".join(self.search_dirs)} -maxdepth 4 -name "app/etc/local.xml" 2>/dev/null | head -20',
            'prestashop': f'find {" ".join(self.search_dirs)} -maxdepth 4 -path "*/config/settings.inc.php" 2>/dev/null | head -20',
            'moodle': f'find {" ".join(self.search_dirs)} -maxdepth 4 -name "config.php" -path "*/moodle/*" 2>/dev/null | head -20',
            'mediawiki': f'find {" ".join(self.search_dirs)} -maxdepth 4 -name "LocalSettings.php" 2>/dev/null | head -20'
        }
        
        results = self.discovery.execute_commands_parallel(cms_checks, timeout=15)
        
        for cms_name, result in results.items():
            if result.get('success') and result['stdout'].strip():
                installations = []
                for path in result['stdout'].splitlines():
                    if path:
                        installations.append(str(Path(path).parent))
                if installations:
                    frameworks[cms_name] = installations
        
        return frameworks
    
    def _detect_static_sites(self) -> Dict[str, Any]:
        """Detect static site generators"""
        static_sites = {}
        
        commands = {
            'jekyll': f'find {" ".join(self.search_dirs)} -maxdepth 4 -name "_config.yml" -o -name "jekyll.yml" 2>/dev/null | head -20',
            'hugo': f'find {" ".join(self.search_dirs)} -maxdepth 4 -name "hugo.toml" -o -name "hugo.yaml" -o -name "config.toml" 2>/dev/null | head -20',
            'gatsby': f'find {" ".join(self.search_dirs)} -maxdepth 4 -name "gatsby-config.js" 2>/dev/null | head -20',
            'hexo': f'find {" ".join(self.search_dirs)} -maxdepth 4 -name "_config.yml" -path "*hexo*" 2>/dev/null | head -20'
        }
        
        results = self.discovery.execute_commands_parallel(commands, timeout=15)
        
        for generator, result in results.items():
            if result.get('success') and result['stdout'].strip():
                sites = []
                for path in result['stdout'].splitlines():
                    if path:
                        sites.append(str(Path(path).parent))
                if sites:
                    static_sites[generator] = sites
        
        return static_sites
    
    def _collect_manifests(self) -> List[Dict]:
        """Collect application dependency manifests"""
        manifests = []
        
        manifest_patterns = [
            'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
            'composer.json', 'composer.lock',
            'requirements.txt', 'Pipfile', 'Pipfile.lock', 'poetry.lock', 'pyproject.toml',
            'Gemfile', 'Gemfile.lock',
            'pom.xml', 'build.gradle', 'build.gradle.kts',
            'Cargo.toml', 'Cargo.lock',
            'go.mod', 'go.sum'
        ]
        
        find_cmd = f'find {" ".join(self.search_dirs[:3])} -maxdepth 4 \\( '
        find_cmd += ' -o '.join([f'-name "{pattern}"' for pattern in manifest_patterns])
        find_cmd += ' \\) 2>/dev/null | head -50'
        
        result = self.discovery.execute_command(find_cmd, timeout=20)
        
        if result.get('success'):
            for path in result['stdout'].splitlines():
                if path:
                    manifests.append({
                        'path': path,
                        'type': Path(path).name,
                        'directory': str(Path(path).parent)
                    })
        
        return manifests
    
    def _collect_process_info(self) -> Dict[str, Any]:
        """Collect information about running application processes"""
        process_info = {}
        
        # Get top processes by CPU and memory
        commands = {
            'top_cpu': 'ps aux --sort=-%cpu | head -20',
            'top_memory': 'ps aux --sort=-%mem | head -20',
            'web_servers': 'ps aux | grep -E "(apache|nginx|caddy|lighttpd)" | grep -v grep || true',
            'app_servers': 'ps aux | grep -E "(tomcat|jetty|uwsgi|gunicorn|puma|unicorn|passenger)" | grep -v grep || true'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # Parse top CPU processes
        if results.get('top_cpu', {}).get('success'):
            cpu_processes = []
            lines = results['top_cpu']['stdout'].splitlines()[1:]  # Skip header
            for line in lines[:10]:
                parts = line.split(None, 10)
                if len(parts) > 10:
                    cpu_processes.append({
                        'user': parts[0],
                        'pid': parts[1],
                        'cpu': parts[2],
                        'mem': parts[3],
                        'command': parts[10][:100]
                    })
            process_info['top_cpu'] = cpu_processes
        
        # Parse top memory processes
        if results.get('top_memory', {}).get('success'):
            mem_processes = []
            lines = results['top_memory']['stdout'].splitlines()[1:]  # Skip header
            for line in lines[:10]:
                parts = line.split(None, 10)
                if len(parts) > 10:
                    mem_processes.append({
                        'user': parts[0],
                        'pid': parts[1],
                        'cpu': parts[2],
                        'mem': parts[3],
                        'command': parts[10][:100]
                    })
            process_info['top_memory'] = mem_processes
        
        # Web servers
        if results.get('web_servers', {}).get('success') and results['web_servers']['stdout']:
            process_info['web_servers'] = len(results['web_servers']['stdout'].splitlines())
        
        # Application servers
        if results.get('app_servers', {}).get('success') and results['app_servers']['stdout']:
            process_info['app_servers'] = len(results['app_servers']['stdout'].splitlines())
        
        return process_info