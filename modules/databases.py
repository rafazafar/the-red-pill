import re
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class DatabasesModule:
    def __init__(self, discovery):
        self.discovery = discovery
    
    def collect(self) -> Dict[str, Any]:
        """Collect database server information"""
        logger.info("Collecting database information...")
        
        databases = {
            'mysql': self._collect_mysql_info(),
            'postgresql': self._collect_postgresql_info(),
            'mongodb': self._collect_mongodb_info(),
            'redis': self._collect_redis_info(),
            'elasticsearch': self._collect_elasticsearch_info(),
            'cassandra': self._collect_cassandra_info(),
            'couchdb': self._collect_couchdb_info(),
            'sqlite': self._collect_sqlite_databases(),
            'memcached': self._collect_memcached_info()
        }
        
        return databases
    
    def _collect_mysql_info(self) -> Dict[str, Any]:
        """Collect MySQL/MariaDB information"""
        mysql_info = {}
        
        commands = {
            'mysql_version': 'mysql --version 2>/dev/null',
            'mysqld_version': 'mysqld --version 2>/dev/null',
            'mariadb_version': 'mariadb --version 2>/dev/null',
            'mysql_status': 'systemctl status mysql 2>/dev/null || service mysql status 2>/dev/null',
            'mariadb_status': 'systemctl status mariadb 2>/dev/null || service mariadb status 2>/dev/null',
            'config_files': 'ls -la /etc/mysql/ 2>/dev/null || ls -la /etc/my.cnf.d/ 2>/dev/null',
            'datadir': 'grep -E "^datadir" /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null || grep -E "^datadir" /etc/my.cnf 2>/dev/null',
            'port': 'grep -E "^port" /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null || grep -E "^port" /etc/my.cnf 2>/dev/null',
            'processes': 'ps aux | grep -E "(mysql|mariadb)" | grep -v grep'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # Version detection
        for version_key in ['mysql_version', 'mysqld_version', 'mariadb_version']:
            if results.get(version_key, {}).get('success') and results[version_key]['stdout']:
                mysql_info['version'] = results[version_key]['stdout'].strip()
                if 'mariadb' in mysql_info['version'].lower():
                    mysql_info['type'] = 'MariaDB'
                else:
                    mysql_info['type'] = 'MySQL'
                break
        
        # Service status
        for status_key in ['mysql_status', 'mariadb_status']:
            if results.get(status_key, {}).get('success'):
                if 'active (running)' in results[status_key]['stdout']:
                    mysql_info['status'] = 'running'
                elif 'inactive' in results[status_key]['stdout']:
                    mysql_info['status'] = 'stopped'
                break
        
        # Configuration
        if results.get('datadir', {}).get('success'):
            datadir_match = re.search(r'datadir\s*=\s*(.+)', results['datadir']['stdout'])
            if datadir_match:
                mysql_info['data_directory'] = datadir_match.group(1).strip()
        
        if results.get('port', {}).get('success'):
            port_match = re.search(r'port\s*=\s*(\d+)', results['port']['stdout'])
            if port_match:
                mysql_info['port'] = int(port_match.group(1))
        
        # Configuration files
        if results.get('config_files', {}).get('success'):
            configs = []
            for line in results['config_files']['stdout'].splitlines():
                if '.cnf' in line or '.conf' in line:
                    parts = line.split()
                    if len(parts) >= 9:
                        configs.append(parts[8])
            if configs:
                mysql_info['config_files'] = configs
        
        # Running processes
        if results.get('processes', {}).get('success') and results['processes']['stdout']:
            mysql_info['processes'] = len(results['processes']['stdout'].splitlines())
        
        return mysql_info
    
    def _collect_postgresql_info(self) -> Dict[str, Any]:
        """Collect PostgreSQL information"""
        postgres_info = {}
        
        commands = {
            'version': 'psql --version 2>/dev/null || postgres --version 2>/dev/null',
            'status': 'systemctl status postgresql 2>/dev/null || service postgresql status 2>/dev/null',
            'config': 'find /etc/postgresql /var/lib/postgresql -name "postgresql.conf" 2>/dev/null | head -5',
            'clusters': 'pg_lsclusters 2>/dev/null',
            'processes': 'ps aux | grep postgres | grep -v grep',
            'data_dirs': 'find /var/lib/postgresql -maxdepth 3 -name "PG_VERSION" 2>/dev/null'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # Version
        if results.get('version', {}).get('success'):
            postgres_info['version'] = results['version']['stdout'].strip()
        
        # Service status
        if results.get('status', {}).get('success'):
            if 'active (running)' in results['status']['stdout']:
                postgres_info['status'] = 'running'
            elif 'inactive' in results['status']['stdout']:
                postgres_info['status'] = 'stopped'
        
        # Clusters (Debian/Ubuntu)
        if results.get('clusters', {}).get('success') and results['clusters']['stdout']:
            clusters = []
            for line in results['clusters']['stdout'].splitlines()[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 5:
                    clusters.append({
                        'version': parts[0],
                        'cluster': parts[1],
                        'port': parts[2],
                        'status': parts[3]
                    })
            if clusters:
                postgres_info['clusters'] = clusters
        
        # Configuration files
        if results.get('config', {}).get('success') and results['config']['stdout']:
            postgres_info['config_files'] = results['config']['stdout'].splitlines()
        
        # Data directories
        if results.get('data_dirs', {}).get('success') and results['data_dirs']['stdout']:
            data_dirs = []
            for path in results['data_dirs']['stdout'].splitlines():
                if path:
                    data_dirs.append(str(path).replace('/PG_VERSION', ''))
            if data_dirs:
                postgres_info['data_directories'] = data_dirs
        
        # Processes
        if results.get('processes', {}).get('success') and results['processes']['stdout']:
            process_lines = results['processes']['stdout'].splitlines()
            postgres_info['process_count'] = len(process_lines)
            
            # Identify main process
            for line in process_lines:
                if 'postgres:' in line or 'postmaster' in line:
                    if 'writer' in line:
                        postgres_info['background_writer'] = True
                    elif 'checkpointer' in line:
                        postgres_info['checkpointer'] = True
                    elif 'walwriter' in line:
                        postgres_info['wal_writer'] = True
        
        return postgres_info
    
    def _collect_mongodb_info(self) -> Dict[str, Any]:
        """Collect MongoDB information"""
        mongodb_info = {}
        
        commands = {
            'version': 'mongod --version 2>/dev/null | head -1',
            'mongo_version': 'mongo --version 2>/dev/null | head -1',
            'status': 'systemctl status mongod 2>/dev/null || service mongod status 2>/dev/null',
            'config': 'cat /etc/mongod.conf 2>/dev/null || cat /etc/mongodb.conf 2>/dev/null',
            'processes': 'ps aux | grep mongod | grep -v grep'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # Version
        if results.get('version', {}).get('success'):
            mongodb_info['version'] = results['version']['stdout'].strip()
        elif results.get('mongo_version', {}).get('success'):
            mongodb_info['version'] = results['mongo_version']['stdout'].strip()
        
        # Service status
        if results.get('status', {}).get('success'):
            if 'active (running)' in results['status']['stdout']:
                mongodb_info['status'] = 'running'
            elif 'inactive' in results['status']['stdout']:
                mongodb_info['status'] = 'stopped'
        
        # Configuration
        if results.get('config', {}).get('success'):
            config = results['config']['stdout']
            # Extract key configuration items
            if 'dbPath:' in config:
                dbpath_match = re.search(r'dbPath:\s*(.+)', config)
                if dbpath_match:
                    mongodb_info['db_path'] = dbpath_match.group(1).strip()
            
            if 'port:' in config:
                port_match = re.search(r'port:\s*(\d+)', config)
                if port_match:
                    mongodb_info['port'] = int(port_match.group(1))
            
            if 'bindIp:' in config:
                bindip_match = re.search(r'bindIp:\s*(.+)', config)
                if bindip_match:
                    mongodb_info['bind_ip'] = bindip_match.group(1).strip()
        
        # Processes
        if results.get('processes', {}).get('success') and results['processes']['stdout']:
            mongodb_info['processes'] = len(results['processes']['stdout'].splitlines())
        
        return mongodb_info
    
    def _collect_redis_info(self) -> Dict[str, Any]:
        """Collect Redis information"""
        redis_info = {}
        
        commands = {
            'version': 'redis-server --version 2>/dev/null',
            'cli_version': 'redis-cli --version 2>/dev/null',
            'status': 'systemctl status redis 2>/dev/null || systemctl status redis-server 2>/dev/null',
            'config': 'cat /etc/redis/redis.conf 2>/dev/null || cat /etc/redis.conf 2>/dev/null',
            'processes': 'ps aux | grep redis-server | grep -v grep',
            'sentinel': 'ps aux | grep redis-sentinel | grep -v grep'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # Version
        if results.get('version', {}).get('success'):
            redis_info['version'] = results['version']['stdout'].strip()
        elif results.get('cli_version', {}).get('success'):
            redis_info['cli_version'] = results['cli_version']['stdout'].strip()
        
        # Service status
        if results.get('status', {}).get('success'):
            if 'active (running)' in results['status']['stdout']:
                redis_info['status'] = 'running'
            elif 'inactive' in results['status']['stdout']:
                redis_info['status'] = 'stopped'
        
        # Configuration
        if results.get('config', {}).get('success'):
            config = results['config']['stdout']
            # Extract key configuration items
            for line in config.splitlines():
                if line.startswith('port '):
                    redis_info['port'] = line.split()[1]
                elif line.startswith('bind '):
                    redis_info['bind'] = line.split()[1:]
                elif line.startswith('dir '):
                    redis_info['working_directory'] = line.split()[1]
                elif line.startswith('dbfilename '):
                    redis_info['db_filename'] = line.split()[1]
                elif line.startswith('requirepass '):
                    redis_info['password_protected'] = True
        
        # Processes
        if results.get('processes', {}).get('success') and results['processes']['stdout']:
            redis_info['processes'] = len(results['processes']['stdout'].splitlines())
        
        # Sentinel
        if results.get('sentinel', {}).get('success') and results['sentinel']['stdout']:
            redis_info['sentinel_processes'] = len(results['sentinel']['stdout'].splitlines())
        
        return redis_info
    
    def _collect_elasticsearch_info(self) -> Dict[str, Any]:
        """Collect Elasticsearch information"""
        es_info = {}
        
        commands = {
            'version': 'curl -s localhost:9200 2>/dev/null | grep version',
            'status': 'systemctl status elasticsearch 2>/dev/null',
            'config': 'cat /etc/elasticsearch/elasticsearch.yml 2>/dev/null',
            'processes': 'ps aux | grep elasticsearch | grep -v grep'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        # Version from API
        if results.get('version', {}).get('success') and 'version' in results['version']['stdout']:
            es_info['api_response'] = results['version']['stdout'][:500]
        
        # Service status
        if results.get('status', {}).get('success'):
            if 'active (running)' in results['status']['stdout']:
                es_info['status'] = 'running'
            elif 'inactive' in results['status']['stdout']:
                es_info['status'] = 'stopped'
        
        # Configuration
        if results.get('config', {}).get('success'):
            config = results['config']['stdout']
            for line in config.splitlines():
                if 'cluster.name:' in line:
                    es_info['cluster_name'] = line.split(':')[1].strip()
                elif 'node.name:' in line:
                    es_info['node_name'] = line.split(':')[1].strip()
                elif 'path.data:' in line:
                    es_info['data_path'] = line.split(':')[1].strip()
                elif 'network.host:' in line:
                    es_info['network_host'] = line.split(':')[1].strip()
        
        # Processes
        if results.get('processes', {}).get('success') and results['processes']['stdout']:
            es_info['processes'] = len(results['processes']['stdout'].splitlines())
        
        return es_info
    
    def _collect_cassandra_info(self) -> Dict[str, Any]:
        """Collect Cassandra information"""
        cassandra_info = {}
        
        commands = {
            'version': 'cassandra -v 2>/dev/null',
            'nodetool': 'nodetool version 2>/dev/null',
            'status': 'systemctl status cassandra 2>/dev/null',
            'config': 'cat /etc/cassandra/cassandra.yaml 2>/dev/null',
            'processes': 'ps aux | grep cassandra | grep -v grep'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        if results.get('version', {}).get('success'):
            cassandra_info['version'] = results['version']['stdout'].strip()
        elif results.get('nodetool', {}).get('success'):
            cassandra_info['nodetool_version'] = results['nodetool']['stdout'].strip()
        
        if results.get('status', {}).get('success'):
            if 'active (running)' in results['status']['stdout']:
                cassandra_info['status'] = 'running'
        
        if results.get('processes', {}).get('success') and results['processes']['stdout']:
            cassandra_info['processes'] = len(results['processes']['stdout'].splitlines())
        
        return cassandra_info
    
    def _collect_couchdb_info(self) -> Dict[str, Any]:
        """Collect CouchDB information"""
        couchdb_info = {}
        
        commands = {
            'version': 'curl -s localhost:5984 2>/dev/null',
            'status': 'systemctl status couchdb 2>/dev/null',
            'config': 'cat /etc/couchdb/local.ini 2>/dev/null',
            'processes': 'ps aux | grep couchdb | grep -v grep'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        if results.get('version', {}).get('success') and 'couchdb' in results['version']['stdout'].lower():
            couchdb_info['api_response'] = results['version']['stdout'][:200]
        
        if results.get('status', {}).get('success'):
            if 'active (running)' in results['status']['stdout']:
                couchdb_info['status'] = 'running'
        
        if results.get('processes', {}).get('success') and results['processes']['stdout']:
            couchdb_info['processes'] = len(results['processes']['stdout'].splitlines())
        
        return couchdb_info
    
    def _collect_sqlite_databases(self) -> List[str]:
        """Find SQLite database files"""
        sqlite_dbs = []
        
        search_dirs = ['/var/www', '/srv', '/opt', '/home']
        find_cmd = f'find {" ".join(search_dirs)} -maxdepth 5 -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | head -50'
        
        result = self.discovery.execute_command(find_cmd, timeout=15)
        
        if result.get('success'):
            for path in result['stdout'].splitlines():
                if path:
                    # Verify it's actually a SQLite database
                    check_cmd = f'file {path} 2>/dev/null'
                    check_result = self.discovery.execute_command(check_cmd, timeout=5)
                    if check_result.get('success') and 'SQLite' in check_result['stdout']:
                        sqlite_dbs.append(path)
        
        return sqlite_dbs
    
    def _collect_memcached_info(self) -> Dict[str, Any]:
        """Collect Memcached information"""
        memcached_info = {}
        
        commands = {
            'version': 'memcached -V 2>/dev/null',
            'status': 'systemctl status memcached 2>/dev/null',
            'config': 'cat /etc/memcached.conf 2>/dev/null || cat /etc/sysconfig/memcached 2>/dev/null',
            'processes': 'ps aux | grep memcached | grep -v grep'
        }
        
        results = self.discovery.execute_commands_parallel(commands)
        
        if results.get('version', {}).get('success'):
            memcached_info['version'] = results['version']['stdout'].strip()
        
        if results.get('status', {}).get('success'):
            if 'active (running)' in results['status']['stdout']:
                memcached_info['status'] = 'running'
        
        if results.get('config', {}).get('success'):
            config = results['config']['stdout']
            for line in config.splitlines():
                if '-p ' in line or 'PORT=' in line:
                    port_match = re.search(r'(\d+)', line)
                    if port_match:
                        memcached_info['port'] = int(port_match.group(1))
                elif '-m ' in line or 'CACHESIZE=' in line:
                    mem_match = re.search(r'(\d+)', line)
                    if mem_match:
                        memcached_info['memory_limit'] = f'{mem_match.group(1)} MB'
        
        if results.get('processes', {}).get('success') and results['processes']['stdout']:
            memcached_info['processes'] = len(results['processes']['stdout'].splitlines())
        
        return memcached_info