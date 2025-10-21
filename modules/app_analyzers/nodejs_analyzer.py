import re
import json
from typing import Dict, Any, List, Optional
import logging
from .base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class NodeJSAnalyzer(BaseAnalyzer):
    """Comprehensive Node.js ecosystem analyzer covering frameworks, build tools, and deployment requirements"""
    
    @property
    def framework_name(self) -> str:
        return "Node.js"
    
    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive Node.js application analysis"""
        logger.info(f"Starting comprehensive Node.js analysis for {self.app_path}")
        
        analysis = {
            'runtime': self.analyze_runtime_requirements(),
            'framework_stack': self.analyze_framework_stack(),
            'dependencies': self.analyze_dependencies(),
            'build_system': self.analyze_build_system(),
            'process_management': self.analyze_process_management(),
            'database_connections': self.analyze_database_connections(),
            'environment_config': self.analyze_environment_config(),
            'security_config': self.analyze_security_config(),
            'deployment_config': self.analyze_deployment_config(),
            'development_tools': self.analyze_development_tools(),
            'startup_commands': self.generate_startup_commands(),
            'system_requirements': self.generate_system_requirements(),
            'deployment_checklist': self.generate_deployment_checklist(),
            'warnings': self.generate_security_warnings()
        }
        
        return analysis
    
    def analyze_runtime_requirements(self) -> Dict[str, Any]:
        """Analyze Node.js runtime requirements"""
        runtime_info = {}
        
        # Parse package.json for Node.js version
        package_json = self.read_json_file('package.json')
        
        if package_json:
            # Node.js version requirement
            if 'engines' in package_json:
                engines = package_json['engines']
                if 'node' in engines:
                    runtime_info['node_version_requirement'] = engines['node']
                    runtime_info['node_constraint'] = self.parse_version_constraint(engines['node'])
                if 'npm' in engines:
                    runtime_info['npm_version_requirement'] = engines['npm']
            
            # Project metadata
            if 'name' in package_json:
                runtime_info['project_name'] = package_json['name']
            if 'version' in package_json:
                runtime_info['project_version'] = package_json['version']
            if 'description' in package_json:
                runtime_info['description'] = package_json['description']
        
        # Check for package manager lock files
        lock_files = {}
        if self.file_exists('package-lock.json'):
            lock_files['npm'] = 'package-lock.json'
        if self.file_exists('yarn.lock'):
            lock_files['yarn'] = 'yarn.lock'
        if self.file_exists('pnpm-lock.yaml'):
            lock_files['pnpm'] = 'pnpm-lock.yaml'
        if self.file_exists('bun.lockb'):
            lock_files['bun'] = 'bun.lockb'
        
        if lock_files:
            runtime_info['package_managers'] = lock_files
        
        # Check for .nvmrc
        if self.file_exists('.nvmrc'):
            nvmrc_content = self.read_file('.nvmrc').strip()
            if nvmrc_content:
                runtime_info['nvmrc_version'] = nvmrc_content
        
        return runtime_info
    
    def analyze_framework_stack(self) -> Dict[str, Any]:
        """Analyze framework stack and architecture"""
        framework_info = {}
        
        package_json = self.read_json_file('package.json')
        if not package_json:
            return framework_info
        
        dependencies = {**package_json.get('dependencies', {}), **package_json.get('devDependencies', {})}
        
        # Backend frameworks
        backend_frameworks = self._detect_backend_frameworks(dependencies)
        if backend_frameworks:
            framework_info['backend'] = backend_frameworks
        
        # Frontend frameworks
        frontend_frameworks = self._detect_frontend_frameworks(dependencies)
        if frontend_frameworks:
            framework_info['frontend'] = frontend_frameworks
        
        # Meta-frameworks (full-stack)
        meta_frameworks = self._detect_meta_frameworks(dependencies)
        if meta_frameworks:
            framework_info['meta_frameworks'] = meta_frameworks
        
        # Determine primary architecture
        framework_info['architecture'] = self._determine_architecture(backend_frameworks, frontend_frameworks, meta_frameworks)
        
        return framework_info
    
    def _detect_backend_frameworks(self, dependencies: Dict[str, str]) -> Dict[str, Any]:
        """Detect backend Node.js frameworks"""
        backend_frameworks = {}
        
        # Express and Express-based frameworks
        if 'express' in dependencies:
            backend_frameworks['express'] = {
                'version': dependencies['express'],
                'type': 'web_framework'
            }
        
        # NestJS
        if '@nestjs/core' in dependencies:
            backend_frameworks['nestjs'] = {
                'version': dependencies['@nestjs/core'],
                'type': 'enterprise_framework',
                'decorator_based': True
            }
        
        # Fastify
        if 'fastify' in dependencies:
            backend_frameworks['fastify'] = {
                'version': dependencies['fastify'],
                'type': 'web_framework',
                'performance_focused': True
            }
        
        # Koa
        if 'koa' in dependencies:
            backend_frameworks['koa'] = {
                'version': dependencies['koa'],
                'type': 'web_framework',
                'async_focused': True
            }
        
        # Hapi
        if '@hapi/hapi' in dependencies:
            backend_frameworks['hapi'] = {
                'version': dependencies['@hapi/hapi'],
                'type': 'web_framework'
            }
        
        return backend_frameworks
    
    def _detect_frontend_frameworks(self, dependencies: Dict[str, str]) -> Dict[str, Any]:
        """Detect frontend frameworks and libraries"""
        frontend_frameworks = {}
        
        # React ecosystem
        if 'react' in dependencies:
            react_info = {
                'version': dependencies['react'],
                'type': 'library',
                'ecosystem': []
            }
            
            # React ecosystem packages
            react_packages = ['react-dom', 'react-router', 'react-router-dom', '@reduxjs/toolkit', 'redux']
            for package in react_packages:
                if package in dependencies:
                    react_info['ecosystem'].append({
                        'name': package,
                        'version': dependencies[package]
                    })
            
            frontend_frameworks['react'] = react_info
        
        # Vue ecosystem
        if 'vue' in dependencies:
            vue_info = {
                'version': dependencies['vue'],
                'type': 'framework',
                'ecosystem': []
            }
            
            # Vue ecosystem packages
            vue_packages = ['vue-router', 'vuex', 'pinia', '@vue/composition-api']
            for package in vue_packages:
                if package in dependencies:
                    vue_info['ecosystem'].append({
                        'name': package,
                        'version': dependencies[package]
                    })
            
            frontend_frameworks['vue'] = vue_info
        
        # Angular
        if '@angular/core' in dependencies:
            angular_info = {
                'version': dependencies['@angular/core'],
                'type': 'framework',
                'ecosystem': []
            }
            
            # Angular ecosystem packages
            angular_packages = ['@angular/router', '@angular/forms', '@angular/common', '@angular/cli']
            for package in angular_packages:
                if package in dependencies:
                    angular_info['ecosystem'].append({
                        'name': package,
                        'version': dependencies[package]
                    })
            
            frontend_frameworks['angular'] = angular_info
        
        # Svelte
        if 'svelte' in dependencies:
            frontend_frameworks['svelte'] = {
                'version': dependencies['svelte'],
                'type': 'compiler'
            }
        
        # Alpine.js
        if 'alpinejs' in dependencies:
            frontend_frameworks['alpine'] = {
                'version': dependencies['alpinejs'],
                'type': 'lightweight_framework'
            }
        
        return frontend_frameworks
    
    def _detect_meta_frameworks(self, dependencies: Dict[str, str]) -> Dict[str, Any]:
        """Detect meta-frameworks (full-stack frameworks)"""
        meta_frameworks = {}
        
        # Next.js
        if 'next' in dependencies:
            meta_frameworks['nextjs'] = {
                'version': dependencies['next'],
                'type': 'react_meta_framework',
                'features': ['ssr', 'static_generation', 'api_routes']
            }
        
        # Nuxt.js
        if 'nuxt' in dependencies or 'nuxt3' in dependencies:
            version = dependencies.get('nuxt', dependencies.get('nuxt3'))
            meta_frameworks['nuxtjs'] = {
                'version': version,
                'type': 'vue_meta_framework',
                'features': ['ssr', 'static_generation', 'auto_routing']
            }
        
        # SvelteKit
        if '@sveltejs/kit' in dependencies:
            meta_frameworks['sveltekit'] = {
                'version': dependencies['@sveltejs/kit'],
                'type': 'svelte_meta_framework',
                'features': ['ssr', 'static_generation', 'file_based_routing']
            }
        
        # Gatsby
        if 'gatsby' in dependencies:
            meta_frameworks['gatsby'] = {
                'version': dependencies['gatsby'],
                'type': 'static_site_generator',
                'features': ['static_generation', 'graphql', 'plugins']
            }
        
        # Remix
        if '@remix-run/node' in dependencies:
            meta_frameworks['remix'] = {
                'version': dependencies['@remix-run/node'],
                'type': 'react_meta_framework',
                'features': ['ssr', 'nested_routing', 'form_handling']
            }
        
        return meta_frameworks
    
    def _determine_architecture(self, backend: Dict, frontend: Dict, meta: Dict) -> str:
        """Determine the overall application architecture"""
        if meta:
            if 'nextjs' in meta or 'nuxtjs' in meta or 'sveltekit' in meta:
                return 'full_stack_meta_framework'
            elif 'gatsby' in meta:
                return 'static_site_generator'
        
        if backend and frontend:
            return 'spa_with_api'
        elif backend:
            return 'api_only'
        elif frontend:
            return 'frontend_only'
        else:
            return 'utility_scripts'
    
    def analyze_dependencies(self) -> Dict[str, Any]:
        """Analyze dependencies and categorize them"""
        dependency_analysis = {}
        
        package_json = self.read_json_file('package.json')
        if not package_json:
            return dependency_analysis
        
        # Production dependencies
        production_deps = package_json.get('dependencies', {})
        dev_deps = package_json.get('devDependencies', {})
        
        dependency_analysis['dependency_counts'] = {
            'production': len(production_deps),
            'development': len(dev_deps),
            'total': len(production_deps) + len(dev_deps)
        }
        
        # Categorize production dependencies
        if production_deps:
            dependency_analysis['production_categories'] = self.categorize_dependencies(production_deps)
        
        # Categorize development dependencies
        if dev_deps:
            dependency_analysis['development_categories'] = self.categorize_dependencies(dev_deps)
        
        # Security audit information
        dependency_analysis['audit_info'] = self._analyze_security_packages(production_deps, dev_deps)
        
        return dependency_analysis
    
    def _analyze_security_packages(self, prod_deps: Dict, dev_deps: Dict) -> Dict[str, Any]:
        """Analyze security-related packages"""
        security_info = {}
        
        all_deps = {**prod_deps, **dev_deps}
        
        # Security packages
        security_packages = [
            'helmet', 'cors', 'express-rate-limit', 'bcrypt', 'bcryptjs',
            'jsonwebtoken', 'passport', 'express-validator', 'xss'
        ]
        
        found_security = []
        for package in security_packages:
            if package in all_deps:
                found_security.append({
                    'name': package,
                    'version': all_deps[package]
                })
        
        if found_security:
            security_info['security_packages'] = found_security
        
        # Check for potential security issues
        warnings = []
        
        # Old/vulnerable packages (simplified check)
        if 'express' in all_deps:
            express_version = all_deps['express']
            if express_version.startswith('^3') or express_version.startswith('3'):
                warnings.append("Express version appears to be very old")
        
        if warnings:
            security_info['warnings'] = warnings
        
        return security_info
    
    def analyze_build_system(self) -> Dict[str, Any]:
        """Analyze build system and tooling"""
        build_info = {}
        
        package_json = self.read_json_file('package.json')
        if not package_json:
            return build_info
        
        dependencies = {**package_json.get('dependencies', {}), **package_json.get('devDependencies', {})}
        
        # Build tools
        build_tools = {}
        
        # Webpack
        if 'webpack' in dependencies:
            build_tools['webpack'] = {
                'version': dependencies['webpack'],
                'type': 'bundler'
            }
        
        # Vite
        if 'vite' in dependencies:
            build_tools['vite'] = {
                'version': dependencies['vite'],
                'type': 'build_tool',
                'features': ['fast_hmr', 'es_modules']
            }
        
        # Rollup
        if 'rollup' in dependencies:
            build_tools['rollup'] = {
                'version': dependencies['rollup'],
                'type': 'bundler'
            }
        
        # Parcel
        if 'parcel' in dependencies:
            build_tools['parcel'] = {
                'version': dependencies['parcel'],
                'type': 'bundler',
                'features': ['zero_config']
            }
        
        # ESBuild
        if 'esbuild' in dependencies:
            build_tools['esbuild'] = {
                'version': dependencies['esbuild'],
                'type': 'bundler',
                'features': ['ultra_fast']
            }
        
        if build_tools:
            build_info['build_tools'] = build_tools
        
        # Build scripts
        if 'scripts' in package_json:
            scripts = package_json['scripts']
            build_scripts = {}
            
            script_categories = {
                'build': ['build', 'compile', 'bundle'],
                'dev': ['dev', 'develop', 'start:dev', 'serve'],
                'start': ['start', 'serve', 'preview'],
                'test': ['test', 'jest', 'spec'],
                'lint': ['lint', 'eslint', 'prettier'],
                'watch': ['watch', 'dev:watch'],
            }
            
            for category, keywords in script_categories.items():
                matching_scripts = {}
                for script_name, script_cmd in scripts.items():
                    if any(keyword in script_name for keyword in keywords):
                        matching_scripts[script_name] = script_cmd
                
                if matching_scripts:
                    build_scripts[category] = matching_scripts
            
            if build_scripts:
                build_info['scripts'] = build_scripts
        
        # Configuration files
        config_files = []
        build_config_files = [
            'webpack.config.js', 'vite.config.js', 'vite.config.ts',
            'rollup.config.js', 'parcel.config.js', 'esbuild.config.js',
            'babel.config.js', '.babelrc', 'tsconfig.json',
            'tailwind.config.js', 'postcss.config.js'
        ]
        
        for config_file in build_config_files:
            if self.file_exists(config_file):
                config_files.append(config_file)
        
        if config_files:
            build_info['config_files'] = config_files
        
        return build_info
    
    def analyze_process_management(self) -> Dict[str, Any]:
        """Analyze process management and deployment configuration"""
        process_info = {}
        
        # PM2 configuration
        pm2_configs = []
        pm2_files = ['ecosystem.config.js', 'pm2.config.js', 'process.yml', 'process.json']
        
        for pm2_file in pm2_files:
            if self.file_exists(pm2_file):
                pm2_configs.append(pm2_file)
        
        if pm2_configs:
            process_info['pm2_configs'] = pm2_configs
        
        # Docker configuration
        docker_files = []
        docker_file_names = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', '.dockerignore']
        
        for docker_file in docker_file_names:
            if self.file_exists(docker_file):
                docker_files.append(docker_file)
        
        if docker_files:
            process_info['docker_files'] = docker_files
        
        # Kubernetes configuration
        k8s_files = self.find_files('*.yaml') + self.find_files('*.yml')
        k8s_configs = [f for f in k8s_files if any(keyword in f for keyword in ['deployment', 'service', 'ingress', 'configmap'])]
        
        if k8s_configs:
            process_info['kubernetes_configs'] = k8s_configs
        
        # Serverless configuration
        serverless_files = []
        serverless_file_names = ['serverless.yml', 'serverless.yaml', 'vercel.json', 'netlify.toml']
        
        for serverless_file in serverless_file_names:
            if self.file_exists(serverless_file):
                serverless_files.append(serverless_file)
        
        if serverless_files:
            process_info['serverless_configs'] = serverless_files
        
        return process_info
    
    def analyze_database_connections(self) -> Dict[str, Any]:
        """Analyze database connections and ORMs"""
        database_info = {}
        
        package_json = self.read_json_file('package.json')
        if not package_json:
            return database_info
        
        dependencies = {**package_json.get('dependencies', {}), **package_json.get('devDependencies', {})}
        
        # ORMs and database clients
        database_packages = {
            'prisma': {'type': 'orm', 'name': 'Prisma'},
            '@prisma/client': {'type': 'orm', 'name': 'Prisma'},
            'typeorm': {'type': 'orm', 'name': 'TypeORM'},
            'sequelize': {'type': 'orm', 'name': 'Sequelize'},
            'mongoose': {'type': 'odm', 'name': 'Mongoose (MongoDB)'},
            'pg': {'type': 'client', 'name': 'PostgreSQL'},
            'mysql2': {'type': 'client', 'name': 'MySQL'},
            'mysql': {'type': 'client', 'name': 'MySQL'},
            'sqlite3': {'type': 'client', 'name': 'SQLite'},
            'redis': {'type': 'client', 'name': 'Redis'},
            'ioredis': {'type': 'client', 'name': 'Redis'},
            'mongodb': {'type': 'client', 'name': 'MongoDB'},
        }
        
        detected_databases = {}
        for package, info in database_packages.items():
            if package in dependencies:
                detected_databases[package] = {
                    'version': dependencies[package],
                    'type': info['type'],
                    'name': info['name']
                }
        
        if detected_databases:
            database_info['packages'] = detected_databases
        
        # Database configuration files
        db_config_files = []
        config_files = ['prisma/schema.prisma', 'ormconfig.json', 'ormconfig.js', 'database.js']
        
        for config_file in config_files:
            if self.file_exists(config_file):
                db_config_files.append(config_file)
        
        if db_config_files:
            database_info['config_files'] = db_config_files
        
        return database_info
    
    def analyze_environment_config(self) -> Dict[str, Any]:
        """Analyze environment configuration"""
        env_config = {}
        
        # Environment files
        env_files = []
        env_file_names = ['.env', '.env.example', '.env.local', '.env.development', '.env.production']
        
        for env_file in env_file_names:
            if self.file_exists(env_file):
                env_files.append(env_file)
        
        if env_files:
            env_config['env_files'] = env_files
        
        # Parse .env.example for template variables
        env_example = self.read_file('.env.example')
        if env_example:
            env_vars = []
            for line in env_example.splitlines():
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    var_name = line.split('=')[0]
                    env_vars.append(var_name)
            env_config['template_variables'] = env_vars
        
        # Environment variable usage in code
        js_files = self.find_files('*.js') + self.find_files('*.ts')
        env_usage = set()
        
        for js_file in js_files[:10]:  # Limit to first 10 files for performance
            content = self.read_file(js_file)
            if content:
                # Find process.env.VAR_NAME patterns
                env_matches = re.findall(r'process\.env\.([A-Z_][A-Z0-9_]*)', content)
                env_usage.update(env_matches)
        
        if env_usage:
            env_config['code_usage'] = sorted(list(env_usage))
        
        return env_config
    
    def analyze_security_config(self) -> Dict[str, Any]:
        """Analyze security configuration"""
        security_info = {}
        
        package_json = self.read_json_file('package.json')
        if not package_json:
            return security_info
        
        dependencies = {**package_json.get('dependencies', {}), **package_json.get('devDependencies', {})}
        
        # Security middleware
        security_middleware = []
        middleware_packages = {
            'helmet': 'HTTP security headers',
            'cors': 'Cross-Origin Resource Sharing',
            'express-rate-limit': 'Rate limiting',
            'express-slow-down': 'Request rate slowing',
            'express-brute': 'Brute force protection',
            'csurf': 'CSRF protection',
            'express-validator': 'Input validation'
        }
        
        for package, description in middleware_packages.items():
            if package in dependencies:
                security_middleware.append({
                    'package': package,
                    'version': dependencies[package],
                    'purpose': description
                })
        
        if security_middleware:
            security_info['middleware'] = security_middleware
        
        # Authentication packages
        auth_packages = []
        auth_package_names = {
            'passport': 'Authentication middleware',
            'jsonwebtoken': 'JWT token handling',
            'bcrypt': 'Password hashing',
            'bcryptjs': 'Password hashing (JS)',
            'oauth2-server': 'OAuth2 server',
            '@auth/express': 'Auth.js for Express'
        }
        
        for package, description in auth_package_names.items():
            if package in dependencies:
                auth_packages.append({
                    'package': package,
                    'version': dependencies[package],
                    'purpose': description
                })
        
        if auth_packages:
            security_info['authentication'] = auth_packages
        
        return security_info
    
    def analyze_deployment_config(self) -> Dict[str, Any]:
        """Analyze deployment configuration"""
        deployment_info = {}
        
        # CI/CD configuration
        ci_files = []
        ci_patterns = [
            '.github/workflows/*.yml',
            '.github/workflows/*.yaml',
            '.gitlab-ci.yml',
            'azure-pipelines.yml',
            'buildspec.yml',
            'Jenkinsfile'
        ]
        
        for pattern in ci_patterns:
            if '*' in pattern:
                matches = self.find_files(pattern.split('/')[-1])
                ci_files.extend([f for f in matches if pattern.replace('*', '').replace('.yml', '').replace('.yaml', '') in f])
            else:
                if self.file_exists(pattern):
                    ci_files.append(pattern)
        
        if ci_files:
            deployment_info['ci_cd_files'] = ci_files
        
        # Deployment platform configurations
        platform_configs = []
        platform_files = {
            'vercel.json': 'Vercel',
            'netlify.toml': 'Netlify',
            'railway.json': 'Railway',
            'fly.toml': 'Fly.io',
            'app.json': 'Heroku',
            'Procfile': 'Heroku/Platform'
        }
        
        for file_name, platform in platform_files.items():
            if self.file_exists(file_name):
                platform_configs.append({
                    'file': file_name,
                    'platform': platform
                })
        
        if platform_configs:
            deployment_info['platform_configs'] = platform_configs
        
        return deployment_info
    
    def analyze_development_tools(self) -> Dict[str, Any]:
        """Analyze development tools and workflows"""
        dev_tools = {}
        
        package_json = self.read_json_file('package.json')
        if not package_json:
            return dev_tools
        
        dev_deps = package_json.get('devDependencies', {})
        
        # Linting and formatting
        linting_tools = []
        linting_packages = {
            'eslint': 'JavaScript linting',
            'prettier': 'Code formatting',
            'stylelint': 'CSS linting',
            'jshint': 'JavaScript hints',
            'tslint': 'TypeScript linting (deprecated)'
        }
        
        for package, description in linting_packages.items():
            if package in dev_deps:
                linting_tools.append({
                    'package': package,
                    'version': dev_deps[package],
                    'purpose': description
                })
        
        if linting_tools:
            dev_tools['linting'] = linting_tools
        
        # Testing frameworks
        testing_tools = []
        testing_packages = {
            'jest': 'Testing framework',
            'mocha': 'Testing framework',
            'cypress': 'E2E testing',
            'playwright': 'E2E testing',
            'vitest': 'Testing framework (Vite)',
            '@testing-library/react': 'React testing utilities',
            'supertest': 'HTTP testing'
        }
        
        for package, description in testing_packages.items():
            if package in dev_deps:
                testing_tools.append({
                    'package': package,
                    'version': dev_deps[package],
                    'purpose': description
                })
        
        if testing_tools:
            dev_tools['testing'] = testing_tools
        
        # TypeScript
        if 'typescript' in dev_deps or self.file_exists('tsconfig.json'):
            typescript_info = {'enabled': True}
            if 'typescript' in dev_deps:
                typescript_info['version'] = dev_deps['typescript']
            if self.file_exists('tsconfig.json'):
                typescript_info['config_file'] = 'tsconfig.json'
            dev_tools['typescript'] = typescript_info
        
        return dev_tools
    
    def generate_startup_commands(self) -> Dict[str, Any]:
        """Generate startup commands for different environments"""
        startup_info = {}
        
        package_json = self.read_json_file('package.json')
        if not package_json:
            return startup_info
        
        scripts = package_json.get('scripts', {})
        
        # Development startup
        dev_commands = []
        if 'dev' in scripts:
            dev_commands.append(f"npm run dev  # {scripts['dev']}")
        elif 'start:dev' in scripts:
            dev_commands.append(f"npm run start:dev  # {scripts['start:dev']}")
        elif 'develop' in scripts:
            dev_commands.append(f"npm run develop  # {scripts['develop']}")
        
        if dev_commands:
            startup_info['development'] = dev_commands
        
        # Production startup
        prod_commands = []
        if 'start' in scripts:
            prod_commands.append(f"npm start  # {scripts['start']}")
        elif 'serve' in scripts:
            prod_commands.append(f"npm run serve  # {scripts['serve']}")
        
        # Build commands
        build_commands = []
        if 'build' in scripts:
            build_commands.append(f"npm run build  # {scripts['build']}")
        
        if build_commands:
            startup_info['build'] = build_commands
        
        if prod_commands:
            startup_info['production'] = prod_commands
        
        # PM2 startup (if PM2 config exists)
        if self.file_exists('ecosystem.config.js'):
            startup_info['pm2'] = ['pm2 start ecosystem.config.js']
        
        return startup_info
    
    def generate_system_requirements(self) -> List[Dict[str, str]]:
        """Generate system requirements"""
        requirements = []
        
        # Node.js version requirement
        runtime_info = self.analyze_runtime_requirements()
        node_version = runtime_info.get('node_version_requirement', '>=14.0.0')
        
        requirements.append({
            'type': 'runtime',
            'name': 'Node.js',
            'version': node_version,
            'critical': True,
            'reason': 'Application runtime'
        })
        
        # Package manager
        lock_files = runtime_info.get('package_managers', {})
        if 'yarn' in lock_files:
            requirements.append({
                'type': 'package_manager',
                'name': 'Yarn',
                'critical': False,
                'reason': 'Package management (yarn.lock present)'
            })
        elif 'pnpm' in lock_files:
            requirements.append({
                'type': 'package_manager',
                'name': 'pnpm',
                'critical': False,
                'reason': 'Package management (pnpm-lock.yaml present)'
            })
        elif 'bun' in lock_files:
            requirements.append({
                'type': 'package_manager',
                'name': 'Bun',
                'critical': False,
                'reason': 'Package management (bun.lockb present)'
            })
        
        # Database requirements
        database_info = self.analyze_database_connections()
        db_packages = database_info.get('packages', {})
        
        for package, info in db_packages.items():
            if info['type'] in ['client', 'orm', 'odm']:
                db_name = info['name']
                if 'PostgreSQL' in db_name:
                    requirements.append({
                        'type': 'database',
                        'name': 'PostgreSQL',
                        'version': '12+',
                        'critical': True,
                        'reason': 'Application database'
                    })
                elif 'MySQL' in db_name:
                    requirements.append({
                        'type': 'database',
                        'name': 'MySQL',
                        'version': '8.0+',
                        'critical': True,
                        'reason': 'Application database'
                    })
                elif 'MongoDB' in db_name:
                    requirements.append({
                        'type': 'database',
                        'name': 'MongoDB',
                        'version': '4.4+',
                        'critical': True,
                        'reason': 'Application database'
                    })
                elif 'Redis' in db_name:
                    requirements.append({
                        'type': 'cache',
                        'name': 'Redis',
                        'critical': True,
                        'reason': 'Cache/session storage'
                    })
        
        return requirements
    
    def generate_deployment_checklist(self) -> List[str]:
        """Generate Node.js deployment checklist"""
        checklist = [
            "Install Node.js with correct version",
            "Clone application repository",
            "Install dependencies (npm install/yarn install)",
            "Set up environment variables (.env file)",
            "Configure database connections"
        ]
        
        # Build step if needed
        build_system = self.analyze_build_system()
        if build_system.get('scripts', {}).get('build'):
            checklist.append("Run build process (npm run build)")
        
        # Database setup
        database_info = self.analyze_database_connections()
        if database_info.get('packages'):
            checklist.append("Set up and configure database")
            
            # Prisma-specific
            if 'prisma' in database_info.get('packages', {}):
                checklist.extend([
                    "Run database migrations (npx prisma migrate deploy)",
                    "Generate Prisma client (npx prisma generate)"
                ])
        
        # Process management
        process_info = self.analyze_process_management()
        if process_info.get('pm2_configs'):
            checklist.append("Set up PM2 for process management")
        
        if process_info.get('docker_files'):
            checklist.append("Build and run Docker containers")
        
        # Security
        checklist.extend([
            "Configure reverse proxy (nginx/Apache)",
            "Set up SSL certificates",
            "Configure firewall rules",
            "Set appropriate file permissions"
        ])
        
        return checklist
    
    def generate_security_warnings(self) -> List[str]:
        """Generate Node.js security warnings"""
        warnings = []
        
        # Check for development dependencies in production
        package_json = self.read_json_file('package.json')
        if package_json:
            dev_deps = package_json.get('devDependencies', {})
            if dev_deps:
                warnings.append("Ensure development dependencies are not installed in production (use npm ci --production)")
        
        # Check for environment variables
        env_config = self.analyze_environment_config()
        if not env_config.get('env_files'):
            warnings.append("No environment files found - ensure sensitive configuration is not hardcoded")
        
        # Check for security middleware
        security_config = self.analyze_security_config()
        if not security_config.get('middleware'):
            warnings.append("No security middleware detected - consider adding helmet, cors, rate limiting")
        
        # Check for debug/development mode indicators
        env_example = self.read_file('.env.example')
        if 'NODE_ENV=development' in env_example:
            warnings.append("Ensure NODE_ENV is set to 'production' in production environment")
        
        return warnings