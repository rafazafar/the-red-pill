import re
import json
from typing import Dict, Any, List, Optional
import logging
from .base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class LaravelAnalyzer(BaseAnalyzer):
    """Comprehensive Laravel application analyzer based on real-world deployment requirements"""
    
    @property
    def framework_name(self) -> str:
        return "Laravel"
    
    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive Laravel application analysis"""
        logger.info(f"Starting comprehensive Laravel analysis for {self.app_path}")
        
        analysis = {
            'framework': self.analyze_framework_version(),
            'php_environment': self.analyze_php_environment(),
            'environment_config': self.analyze_environment_config(),
            'database': self.analyze_database_config(),
            'scheduled_tasks': self.analyze_scheduled_tasks(),
            'external_services': self.analyze_external_services(),
            'frontend': self.analyze_frontend_stack(),
            'background_workers': self.analyze_background_workers(),
            'file_permissions': self.analyze_file_permissions(),
            'security': self.analyze_security_config(),
            'deployment': self.generate_deployment_analysis(),
            'warnings': self.generate_security_warnings(),
            'requirements': self.generate_system_requirements()
        }
        
        return analysis
    
    def analyze_framework_version(self) -> Dict[str, Any]:
        """Analyze Laravel framework version and core configuration"""
        framework_info = {}
        
        # Parse composer.json for Laravel version
        composer_json = self.read_json_file('composer.json')
        
        if composer_json:
            require = composer_json.get('require', {})
            
            # Laravel framework version
            if 'laravel/framework' in require:
                framework_info['laravel_version'] = require['laravel/framework']
                framework_info['version_constraint'] = self.parse_version_constraint(require['laravel/framework'])
            
            # Check for Laravel packages
            laravel_packages = {}
            for package, version in require.items():
                if package.startswith('laravel/'):
                    laravel_packages[package] = version
            
            if laravel_packages:
                framework_info['laravel_packages'] = laravel_packages
            
            # Project metadata
            if 'name' in composer_json:
                framework_info['project_name'] = composer_json['name']
            if 'description' in composer_json:
                framework_info['description'] = composer_json['description']
        
        # Check Laravel version from artisan
        if self.file_exists('artisan'):
            artisan_version = self.get_command_version('php artisan --version', '')
            if artisan_version:
                framework_info['artisan_version'] = artisan_version
        
        return framework_info
    
    def analyze_php_environment(self) -> Dict[str, Any]:
        """Analyze PHP version requirements and extensions"""
        php_info = {}
        
        composer_json = self.read_json_file('composer.json')
        
        if composer_json:
            require = composer_json.get('require', {})
            
            # PHP version requirement
            if 'php' in require:
                php_info['php_version_requirement'] = require['php']
                php_info['php_constraint'] = self.parse_version_constraint(require['php'])
            
            # PHP extensions
            extensions = []
            for package in require.keys():
                if package.startswith('ext-'):
                    extensions.append(package.replace('ext-', ''))
            
            if extensions:
                php_info['required_extensions'] = extensions
            
            # Platform requirements
            if 'config' in composer_json and 'platform' in composer_json['config']:
                php_info['platform_config'] = composer_json['config']['platform']
        
        return php_info
    
    def analyze_environment_config(self) -> Dict[str, Any]:
        """Analyze environment configuration and variables"""
        env_config = {}
        
        # Read .env.example as template
        env_example = self.read_file('.env.example')
        if env_example:
            env_vars = []
            for line in env_example.splitlines():
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    var_name = line.split('=')[0]
                    env_vars.append(var_name)
            env_config['env_template_vars'] = env_vars
        
        # Analyze config files for environment variable usage
        config_env_vars = set()
        config_files = self.find_files('*.php', max_depth=2)
        
        for config_file in config_files:
            if config_file.startswith('config/'):
                content = self.read_file(config_file)
                if content:
                    vars_in_file = self.extract_env_vars(content)
                    config_env_vars.update(vars_in_file)
        
        if config_env_vars:
            env_config['config_env_vars'] = sorted(list(config_env_vars))
        
        # Analyze specific configuration areas
        env_config.update(self._analyze_config_areas())
        
        return env_config
    
    def _analyze_config_areas(self) -> Dict[str, Any]:
        """Analyze specific Laravel configuration areas"""
        config_analysis = {}
        
        # Cache configuration
        cache_config = self.read_file('config/cache.php')
        if cache_config:
            cache_info = {'drivers': []}
            
            # Extract default driver
            default_match = re.search(r"'default'\s*=>\s*env\('CACHE_DRIVER',\s*'([^']+)'\)", cache_config)
            if default_match:
                cache_info['default_driver'] = default_match.group(1)
            
            # Find all configured stores
            stores_match = re.search(r"'stores'\s*=>\s*\[(.*?)\]", cache_config, re.DOTALL)
            if stores_match:
                store_section = stores_match.group(1)
                drivers = re.findall(r"'([^']+)'\s*=>\s*\[.*?'driver'\s*=>\s*'([^']+)'", store_section, re.DOTALL)
                for store_name, driver in drivers:
                    cache_info['drivers'].append({'store': store_name, 'driver': driver})
            
            config_analysis['cache'] = cache_info
        
        # Queue configuration
        queue_config = self.read_file('config/queue.php')
        if queue_config:
            queue_info = {}
            
            # Extract default connection
            default_match = re.search(r"'default'\s*=>\s*env\('QUEUE_CONNECTION',\s*'([^']+)'\)", queue_config)
            if default_match:
                queue_info['default_connection'] = default_match.group(1)
            
            # Find queue connections
            connections_match = re.search(r"'connections'\s*=>\s*\[(.*?)\]", queue_config, re.DOTALL)
            if connections_match:
                conn_section = connections_match.group(1)
                connections = re.findall(r"'([^']+)'\s*=>\s*\[.*?'driver'\s*=>\s*'([^']+)'", conn_section, re.DOTALL)
                queue_info['connections'] = [{'name': name, 'driver': driver} for name, driver in connections]
            
            config_analysis['queue'] = queue_info
        
        # Database configuration
        database_config = self.read_file('config/database.php')
        if database_config:
            db_info = {}
            
            # Extract default connection
            default_match = re.search(r"'default'\s*=>\s*env\('DB_CONNECTION',\s*'([^']+)'\)", database_config)
            if default_match:
                db_info['default_connection'] = default_match.group(1)
            
            # Find database connections
            connections_match = re.search(r"'connections'\s*=>\s*\[(.*?)\]", database_config, re.DOTALL)
            if connections_match:
                conn_section = connections_match.group(1)
                connections = re.findall(r"'([^']+)'\s*=>\s*\[.*?'driver'\s*=>\s*'([^']+)'", conn_section, re.DOTALL)
                db_info['connections'] = [{'name': name, 'driver': driver} for name, driver in connections]
            
            config_analysis['database'] = db_info
        
        # Session configuration
        session_config = self.read_file('config/session.php')
        if session_config:
            session_info = {}
            
            driver_match = re.search(r"'driver'\s*=>\s*env\('SESSION_DRIVER',\s*'([^']+)'\)", session_config)
            if driver_match:
                session_info['driver'] = driver_match.group(1)
            
            config_analysis['session'] = session_info
        
        # Mail configuration
        mail_config = self.read_file('config/mail.php')
        if mail_config:
            mail_info = {}
            
            default_match = re.search(r"'default'\s*=>\s*env\('MAIL_MAILER',\s*'([^']+)'\)", mail_config)
            if default_match:
                mail_info['default_mailer'] = default_match.group(1)
            
            config_analysis['mail'] = mail_info
        
        # Filesystem configuration
        filesystems_config = self.read_file('config/filesystems.php')
        if filesystems_config:
            fs_info = {}
            
            default_match = re.search(r"'default'\s*=>\s*env\('FILESYSTEM_DISK',\s*'([^']+)'\)", filesystems_config)
            if default_match:
                fs_info['default_disk'] = default_match.group(1)
            
            # Find all disks
            disks_match = re.search(r"'disks'\s*=>\s*\[(.*?)\]", filesystems_config, re.DOTALL)
            if disks_match:
                disk_section = disks_match.group(1)
                disks = re.findall(r"'([^']+)'\s*=>\s*\[.*?'driver'\s*=>\s*'([^']+)'", disk_section, re.DOTALL)
                fs_info['disks'] = [{'name': name, 'driver': driver} for name, driver in disks]
            
            config_analysis['filesystems'] = fs_info
        
        return config_analysis
    
    def analyze_database_config(self) -> Dict[str, Any]:
        """Analyze database configuration, migrations, and seeders"""
        db_analysis = {}
        
        # Migrations
        migration_files = self.find_files('*.php', max_depth=2)
        migrations = [f for f in migration_files if f.startswith('database/migrations/')]
        
        if migrations:
            db_analysis['migrations'] = {
                'count': len(migrations),
                'files': migrations[:20]  # Limit for readability
            }
            
            # Analyze migration complexity
            complex_migrations = []
            for migration in migrations:
                content = self.read_file(migration)
                if any(keyword in content for keyword in ['DB::raw', 'DB::statement', 'foreign', 'index']):
                    complex_migrations.append(migration)
            
            if complex_migrations:
                db_analysis['complex_migrations'] = complex_migrations
        
        # Seeders
        seeder_files = self.find_files('*Seeder.php', max_depth=3)
        seeders = [f for f in seeder_files if f.startswith('database/seeders/')]
        
        if seeders:
            db_analysis['seeders'] = {
                'count': len(seeders),
                'files': seeders
            }
        
        # Database-specific features
        raw_sql_usage = self.grep_files('DB::raw|DB::statement')
        if raw_sql_usage:
            db_analysis['raw_sql_usage'] = raw_sql_usage
        
        return db_analysis
    
    def analyze_scheduled_tasks(self) -> Dict[str, Any]:
        """Analyze Laravel scheduler configuration"""
        scheduler_analysis = {}
        
        # Read Console/Kernel.php
        kernel_content = self.read_file('app/Console/Kernel.php')
        
        if kernel_content:
            # Extract scheduled commands
            schedule_matches = re.findall(
                r'\$schedule->([^;]+);',
                kernel_content,
                re.MULTILINE
            )
            
            if schedule_matches:
                tasks = []
                for match in schedule_matches:
                    # Parse command and frequency
                    task_info = {'raw': match.strip()}
                    
                    # Extract command name
                    if 'command(' in match:
                        cmd_match = re.search(r"command\('([^']+)'", match)
                        if cmd_match:
                            task_info['command'] = cmd_match.group(1)
                    elif 'call(' in match:
                        task_info['type'] = 'closure'
                    elif 'exec(' in match:
                        task_info['type'] = 'shell'
                    
                    # Extract frequency
                    freq_patterns = [
                        ('everyMinute', 'every minute'),
                        ('everyFiveMinutes', 'every 5 minutes'),
                        ('everyTenMinutes', 'every 10 minutes'),
                        ('everyFifteenMinutes', 'every 15 minutes'),
                        ('everyThirtyMinutes', 'every 30 minutes'),
                        ('hourly', 'hourly'),
                        ('daily', 'daily'),
                        ('weekly', 'weekly'),
                        ('monthly', 'monthly'),
                        ('cron(', 'custom cron')
                    ]
                    
                    for pattern, description in freq_patterns:
                        if pattern in match:
                            task_info['frequency'] = description
                            break
                    
                    tasks.append(task_info)
                
                scheduler_analysis['scheduled_tasks'] = tasks
                scheduler_analysis['total_tasks'] = len(tasks)
                
                # Check for high-frequency tasks
                high_freq_tasks = [t for t in tasks if 'everyMinute' in t.get('raw', '') or 'everyFiveMinutes' in t.get('raw', '')]
                if high_freq_tasks:
                    scheduler_analysis['high_frequency_tasks'] = high_freq_tasks
        
        # Find custom artisan commands
        command_files = self.find_files('*.php', max_depth=3)
        custom_commands = [f for f in command_files if f.startswith('app/Console/Commands/')]
        
        if custom_commands:
            scheduler_analysis['custom_commands'] = {
                'count': len(custom_commands),
                'files': custom_commands
            }
        
        return scheduler_analysis
    
    def analyze_external_services(self) -> Dict[str, Any]:
        """Analyze external service integrations"""
        services_analysis = {}
        
        # Get composer dependencies
        composer_json = self.read_json_file('composer.json')
        dependencies = composer_json.get('require', {}) if composer_json else {}
        
        # Categorize external services
        external_services = {
            'payment_processors': [],
            'cloud_services': [],
            'api_clients': [],
            'oauth_providers': [],
            'email_services': [],
            'monitoring': []
        }
        
        # Payment processors
        payment_packages = {
            'stripe/stripe-php': 'Stripe',
            'paypal/rest-api-sdk-php': 'PayPal',
            'square/square': 'Square',
            'braintree/braintree_php': 'Braintree'
        }
        
        for package, service in payment_packages.items():
            if package in dependencies:
                external_services['payment_processors'].append({
                    'name': service,
                    'package': package,
                    'version': dependencies[package]
                })
        
        # Cloud services
        cloud_packages = {
            'aws/aws-sdk-php': 'AWS SDK',
            'google/cloud': 'Google Cloud',
            'league/flysystem-aws-s3-v3': 'AWS S3',
            'pusher/pusher-php-server': 'Pusher'
        }
        
        for package, service in cloud_packages.items():
            if package in dependencies:
                external_services['cloud_services'].append({
                    'name': service,
                    'package': package,
                    'version': dependencies[package]
                })
        
        # HTTP clients
        http_packages = {
            'guzzlehttp/guzzle': 'Guzzle HTTP',
            'illuminate/http': 'Laravel HTTP'
        }
        
        for package, service in http_packages.items():
            if package in dependencies:
                external_services['api_clients'].append({
                    'name': service,
                    'package': package,
                    'version': dependencies[package]
                })
        
        # OAuth and social login
        oauth_packages = {
            'laravel/socialite': 'Laravel Socialite',
            'laravel/passport': 'Laravel Passport',
            'laravel/sanctum': 'Laravel Sanctum'
        }
        
        for package, service in oauth_packages.items():
            if package in dependencies:
                external_services['oauth_providers'].append({
                    'name': service,
                    'package': package,
                    'version': dependencies[package]
                })
        
        # Remove empty categories
        services_analysis = {k: v for k, v in external_services.items() if v}
        
        # Analyze OAuth configuration
        services_config = self.read_file('config/services.php')
        if services_config:
            oauth_services = []
            service_patterns = ['github', 'google', 'facebook', 'twitter', 'linkedin']
            
            for service in service_patterns:
                if f"'{service}'" in services_config:
                    oauth_services.append(service)
            
            if oauth_services:
                services_analysis['oauth_configured'] = oauth_services
        
        return services_analysis
    
    def analyze_frontend_stack(self) -> Dict[str, Any]:
        """Analyze frontend dependencies and build configuration"""
        frontend_analysis = {}
        
        # Check for package.json
        package_json = self.read_json_file('package.json')
        
        if package_json:
            frontend_analysis['node_project'] = True
            
            # Node.js version requirement
            if 'engines' in package_json and 'node' in package_json['engines']:
                frontend_analysis['node_version_requirement'] = package_json['engines']['node']
            
            # Build tools detection
            dependencies = {**package_json.get('dependencies', {}), **package_json.get('devDependencies', {})}
            
            build_tools = {}
            if 'vite' in dependencies:
                build_tools['vite'] = dependencies['vite']
                frontend_analysis['build_system'] = 'Vite'
            elif 'laravel-mix' in dependencies:
                build_tools['laravel-mix'] = dependencies['laravel-mix']
                frontend_analysis['build_system'] = 'Laravel Mix'
            elif 'webpack' in dependencies:
                build_tools['webpack'] = dependencies['webpack']
                frontend_analysis['build_system'] = 'Webpack'
            
            if build_tools:
                frontend_analysis['build_tools'] = build_tools
            
            # Frontend frameworks
            frontend_frameworks = {}
            framework_packages = ['vue', 'react', 'angular', 'svelte', 'alpine']
            
            for framework in framework_packages:
                matching_packages = [pkg for pkg in dependencies.keys() if framework in pkg.lower()]
                if matching_packages:
                    frontend_frameworks[framework] = {
                        'packages': matching_packages,
                        'primary_version': dependencies.get(framework, dependencies.get(f'@{framework}/core', 'unknown'))
                    }
            
            if frontend_frameworks:
                frontend_analysis['frontend_frameworks'] = frontend_frameworks
            
            # Build scripts
            if 'scripts' in package_json:
                scripts = package_json['scripts']
                build_scripts = {}
                
                for script_name, script_cmd in scripts.items():
                    if any(keyword in script_name for keyword in ['build', 'dev', 'watch', 'prod']):
                        build_scripts[script_name] = script_cmd
                
                if build_scripts:
                    frontend_analysis['build_scripts'] = build_scripts
        
        # Check for build configuration files
        build_configs = []
        config_files = ['vite.config.js', 'webpack.mix.js', 'webpack.config.js', 'rollup.config.js']
        
        for config_file in config_files:
            if self.file_exists(config_file):
                build_configs.append(config_file)
        
        if build_configs:
            frontend_analysis['config_files'] = build_configs
        
        # Check if compiled assets are tracked in Git
        if self.file_exists('public/build') or self.file_exists('public/js') or self.file_exists('public/css'):
            # This is a simplified check - in real implementation, you'd check git ls-files
            frontend_analysis['compiled_assets_present'] = True
        
        # Admin panel detection
        admin_analysis = self.analyze_admin_panels()
        if admin_analysis:
            frontend_analysis['admin_panels'] = admin_analysis
        
        return frontend_analysis
    
    def analyze_admin_panels(self) -> Dict[str, Any]:
        """Detect and analyze admin panel configurations"""
        admin_info = {}
        
        # Get composer dependencies
        composer_json = self.read_json_file('composer.json')
        dependencies = composer_json.get('require', {}) if composer_json else {}
        
        # Laravel admin packages
        admin_packages = {
            'encore/laravel-admin': 'Laravel Admin',
            'laravel/nova': 'Laravel Nova',
            'filament/filament': 'Filament',
            'backpack/crud': 'Backpack for Laravel'
        }
        
        detected_admins = {}
        for package, name in admin_packages.items():
            if package in dependencies:
                detected_admins[package] = {
                    'name': name,
                    'version': dependencies[package]
                }
        
        if detected_admins:
            admin_info['packages'] = detected_admins
        
        # Check for Laravel Admin specific setup
        if 'encore/laravel-admin' in dependencies:
            laravel_admin_info = {}
            
            # Check for app/Admin directory
            if self.directory_exists('app/Admin'):
                laravel_admin_info['admin_directory_exists'] = True
            
            # Check for published assets
            if self.directory_exists('public/vendor/laravel-admin'):
                laravel_admin_info['assets_published'] = True
            
            if laravel_admin_info:
                admin_info['laravel_admin_setup'] = laravel_admin_info
        
        return admin_info
    
    def analyze_background_workers(self) -> Dict[str, Any]:
        """Analyze background worker requirements"""
        worker_analysis = {}
        
        # Check for queued jobs
        job_files = self.grep_files('implements ShouldQueue', '*.php')
        
        if job_files:
            worker_analysis['queued_jobs_found'] = True
            worker_analysis['job_files'] = job_files
        
        # Analyze queue configuration
        queue_config = self.read_file('config/queue.php')
        if queue_config:
            # Check if queue is not sync
            if "'sync'" not in queue_config or "env('QUEUE_CONNECTION', 'sync')" not in queue_config:
                worker_analysis['requires_queue_workers'] = True
        
        # Check for WebSocket packages
        composer_json = self.read_json_file('composer.json')
        if composer_json:
            dependencies = composer_json.get('require', {})
            websocket_packages = {
                'beyondcode/laravel-websockets': 'Laravel WebSockets',
                'pusher/pusher-php-server': 'Pusher',
                'ratchet/pawl': 'Ratchet WebSocket'
            }
            
            detected_websockets = {}
            for package, name in websocket_packages.items():
                if package in dependencies:
                    detected_websockets[package] = {
                        'name': name,
                        'version': dependencies[package]
                    }
            
            if detected_websockets:
                worker_analysis['websocket_services'] = detected_websockets
        
        return worker_analysis
    
    def analyze_file_permissions(self) -> Dict[str, Any]:
        """Analyze file permissions and ownership requirements"""
        permissions_analysis = {}
        
        # Check writable directories
        writable_dirs = [
            'storage',
            'storage/framework/cache',
            'storage/framework/sessions',
            'storage/framework/views',
            'storage/logs',
            'bootstrap/cache'
        ]
        
        dir_permissions = {}
        for directory in writable_dirs:
            if self.directory_exists(directory):
                perms = self.get_file_permissions(directory)
                if perms:
                    dir_permissions[directory] = perms
                
                # Check if directory is writable (simplified check)
                size = self.get_directory_size(directory)
                if size:
                    dir_permissions[f"{directory}_size"] = size
        
        if dir_permissions:
            permissions_analysis['directory_permissions'] = dir_permissions
        
        # Check for upload directories
        upload_dirs = ['public/uploads', 'storage/app/uploads']
        existing_upload_dirs = []
        
        for upload_dir in upload_dirs:
            if self.directory_exists(upload_dir):
                existing_upload_dirs.append(upload_dir)
        
        if existing_upload_dirs:
            permissions_analysis['upload_directories'] = existing_upload_dirs
        
        return permissions_analysis
    
    def analyze_security_config(self) -> Dict[str, Any]:
        """Analyze security configuration"""
        security_analysis = {}
        
        # Authentication configuration
        auth_config = self.read_file('config/auth.php')
        if auth_config:
            auth_info = {}
            
            # Extract default guard
            guard_match = re.search(r"'default'\s*=>\s*\[\s*'guard'\s*=>\s*'([^']+)'", auth_config)
            if guard_match:
                auth_info['default_guard'] = guard_match.group(1)
            
            # Extract providers
            providers_match = re.search(r"'providers'\s*=>\s*\[(.*?)\]", auth_config, re.DOTALL)
            if providers_match:
                providers_section = providers_match.group(1)
                providers = re.findall(r"'([^']+)'\s*=>\s*\[.*?'driver'\s*=>\s*'([^']+)'", providers_section, re.DOTALL)
                auth_info['providers'] = [{'name': name, 'driver': driver} for name, driver in providers]
            
            security_analysis['authentication'] = auth_info
        
        # Check for file upload validation
        upload_validation = self.grep_files('mimes:|image|max:', '*.php')
        if upload_validation:
            security_analysis['file_upload_validation'] = len(upload_validation)
        
        # Check for SQL injection prevention
        sql_injection_checks = self.grep_files('where.*\\?|whereRaw|DB::raw', '*.php')
        if sql_injection_checks:
            security_analysis['sql_query_patterns'] = len(sql_injection_checks)
        
        return security_analysis
    
    def generate_deployment_analysis(self) -> Dict[str, Any]:
        """Generate deployment-specific analysis"""
        deployment = {}
        
        # Required optimization commands
        optimization_commands = [
            'composer install --no-dev --optimize-autoloader',
            'php artisan config:cache',
            'php artisan route:cache',
            'php artisan view:cache'
        ]
        
        # Check if route caching is safe (no closures in routes)
        routes_content = self.read_file('routes/web.php') + self.read_file('routes/api.php')
        if 'function(' in routes_content:
            optimization_commands.append('# WARNING: Route caching not safe due to closures in routes')
        
        deployment['optimization_commands'] = optimization_commands
        
        # Environment-specific requirements
        env_requirements = []
        
        # Check if scheduler needs cron
        if self.analyze_scheduled_tasks().get('scheduled_tasks'):
            env_requirements.append('Setup cron job: * * * * * cd /path/to/app && php artisan schedule:run >> /dev/null 2>&1')
        
        # Check if queue workers needed
        if self.analyze_background_workers().get('requires_queue_workers'):
            env_requirements.append('Setup queue workers with Supervisor or systemd')
        
        # Check if Node.js build needed
        if self.read_json_file('package.json'):
            env_requirements.append('Run npm install && npm run build for asset compilation')
        
        deployment['environment_requirements'] = env_requirements
        
        return deployment
    
    def generate_system_requirements(self) -> List[Dict[str, str]]:
        """Generate comprehensive system requirements"""
        requirements = []
        
        # PHP requirements
        php_info = self.analyze_php_environment()
        if php_info.get('php_version_requirement'):
            requirements.append({
                'type': 'runtime',
                'name': 'PHP',
                'version': php_info['php_version_requirement'],
                'critical': True,
                'reason': 'Laravel framework requirement'
            })
        
        if php_info.get('required_extensions'):
            for ext in php_info['required_extensions']:
                requirements.append({
                    'type': 'php_extension',
                    'name': f'php-{ext}',
                    'critical': True,
                    'reason': f'Required PHP extension: {ext}'
                })
        
        # Database requirements
        database_config = self.analyze_environment_config().get('database', {})
        if database_config.get('default_connection'):
            db_driver = database_config['default_connection']
            if db_driver == 'mysql':
                requirements.append({
                    'type': 'database',
                    'name': 'MySQL',
                    'version': '5.7+',
                    'critical': True,
                    'reason': 'Application database'
                })
            elif db_driver == 'pgsql':
                requirements.append({
                    'type': 'database',
                    'name': 'PostgreSQL',
                    'version': '10+',
                    'critical': True,
                    'reason': 'Application database'
                })
        
        # Cache requirements
        cache_config = self.analyze_environment_config().get('cache', {})
        if cache_config.get('default_driver') == 'redis':
            requirements.append({
                'type': 'cache',
                'name': 'Redis',
                'critical': True,
                'reason': 'Cache and session storage'
            })
        
        # Queue requirements
        queue_config = self.analyze_environment_config().get('queue', {})
        if queue_config.get('default_connection') != 'sync':
            connection = queue_config.get('default_connection', 'database')
            if connection == 'redis':
                requirements.append({
                    'type': 'queue',
                    'name': 'Redis',
                    'critical': True,
                    'reason': 'Background job processing'
                })
            elif connection == 'beanstalkd':
                requirements.append({
                    'type': 'queue',
                    'name': 'Beanstalkd',
                    'critical': True,
                    'reason': 'Background job processing'
                })
        
        # Node.js requirements
        frontend_analysis = self.analyze_frontend_stack()
        if frontend_analysis.get('node_project'):
            node_version = frontend_analysis.get('node_version_requirement', '>=14.0.0')
            requirements.append({
                'type': 'runtime',
                'name': 'Node.js',
                'version': node_version,
                'critical': False,
                'reason': 'Frontend asset compilation'
            })
        
        return requirements
    
    def generate_security_warnings(self) -> List[str]:
        """Generate Laravel-specific security warnings"""
        warnings = []
        
        # Check for debug mode
        env_example = self.read_file('.env.example')
        if 'APP_DEBUG=true' in env_example:
            warnings.append("APP_DEBUG is set to true in .env.example - ensure it's false in production")
        
        # Check for default APP_KEY
        if 'APP_KEY=' in env_example and len(env_example.split('APP_KEY=')[1].split('\n')[0]) < 10:
            warnings.append("APP_KEY appears to be empty or default - run php artisan key:generate")
        
        # Check for storage link
        if self.directory_exists('public/storage'):
            warnings.append("Public storage symlink exists - ensure it points to storage/app/public")
        
        # Check .env permissions
        if self.file_exists('.env'):
            perms = self.get_file_permissions('.env')
            if perms and perms not in ['600', '644']:
                warnings.append(f"Environment file (.env) has overly permissive permissions: {perms}")
        
        # Check for hardcoded credentials in config
        config_files = self.find_files('*.php', max_depth=2)
        for config_file in config_files:
            if config_file.startswith('config/'):
                content = self.read_file(config_file)
                if re.search(r"'password'\s*=>\s*'[^']{8,}", content):
                    warnings.append(f"Potential hardcoded password found in {config_file}")
        
        return warnings
    
    def generate_deployment_checklist(self) -> List[str]:
        """Generate Laravel-specific deployment checklist"""
        checklist = [
            "Install PHP with required extensions",
            "Set up database (MySQL/PostgreSQL)",
            "Clone application repository",
            "Copy .env.example to .env and configure",
            "Run: composer install --no-dev --optimize-autoloader",
            "Run: php artisan key:generate",
            "Run: php artisan migrate",
            "Set up file permissions (storage/, bootstrap/cache/)",
            "Configure web server document root to public/",
            "Run optimization commands (config:cache, route:cache, view:cache)"
        ]
        
        # Add conditional steps
        scheduled_tasks = self.analyze_scheduled_tasks()
        if scheduled_tasks.get('scheduled_tasks'):
            checklist.append("Set up cron job for Laravel scheduler")
        
        background_workers = self.analyze_background_workers()
        if background_workers.get('requires_queue_workers'):
            checklist.append("Configure queue workers with Supervisor/systemd")
        
        frontend = self.analyze_frontend_stack()
        if frontend.get('node_project'):
            checklist.extend([
                "Install Node.js and npm",
                "Run: npm install",
                "Run: npm run build"
            ])
        
        admin_panels = frontend.get('admin_panels', {})
        if 'encore/laravel-admin' in admin_panels.get('packages', {}):
            checklist.extend([
                "Run: php artisan admin:install",
                "Run: php artisan vendor:publish --provider=...",
                "Create admin user account"
            ])
        
        return checklist