from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import json
import os
from pathlib import Path
from datetime import datetime
import subprocess
import threading
import requests

app = Flask(__name__, static_folder='build', static_url_path='')
CORS(app)

# Configuration
BASE_DIR = Path(__file__).parent
LOGS_DIR = BASE_DIR / 'logs'
CONFIGS_DIR = BASE_DIR / 'configs'
HONEYPOTS_DIR = BASE_DIR / 'honeypots'

# Store running honeypot processes
running_honeypots = {}

# IP Geolocation cache
ip_location_cache = {}

def get_ip_location(ip):
    """Get location data for an IP address"""
    if ip in ip_location_cache:
        return ip_location_cache[ip]
    
    try:
        # Using ip-api.com (free tier)
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=status,lat,lon,country,city', timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                location = {
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown')
                }
                ip_location_cache[ip] = location
                return location
    except:
        pass
    
    return {'lat': 0, 'lon': 0, 'country': 'Unknown', 'city': 'Unknown'}

def parse_log_file(log_file):
    """Parse a log file and return entries"""
    entries = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    entries.append(entry)
                except:
                    continue
    except:
        pass
    return entries

def parse_session_file(session_file):
    """Parse a session JSON file"""
    try:
        with open(session_file, 'r') as f:
            return json.load(f)
    except:
        return []

def get_all_logs():
    """Get all logs from all honeypot log directories"""
    all_logs = []
    protocols = ['telnet', 'ssh', 'http', 'mqtt', 'dnp3', 'coap', 'modbus']
    
    for protocol in protocols:
        protocol_log_dir = LOGS_DIR / f'{protocol}_honeypot_logs'
        if protocol_log_dir.exists():
            # Parse main log file
            log_file = protocol_log_dir / 'honeypot.log'
            if log_file.exists():
                entries = parse_log_file(log_file)
                for entry in entries:
                    if isinstance(entry, dict):
                        entry['protocol'] = protocol
                        # Add location data
                        if 'ip' in entry:
                            entry['location'] = get_ip_location(entry['ip'])
                        all_logs.append(entry)
            
            # Parse session files
            for session_file in protocol_log_dir.glob('session_*.json'):
                session_data = parse_session_file(session_file)
                if session_data:
                    for entry in session_data:
                        if isinstance(entry, dict):
                            entry['protocol'] = protocol
                            if 'ip' in entry:
                                entry['location'] = get_ip_location(entry['ip'])
                            all_logs.append(entry)
    
    # Sort by timestamp
    all_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return all_logs

def calculate_stats(logs):
    """Calculate statistics from logs"""
    unique_ips = set()
    protocol_counts = {}
    command_count = 0
    
    for log in logs:
        if 'ip' in log:
            unique_ips.add(log['ip'])
        
        protocol = log.get('protocol', 'unknown')
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        if log.get('type') == 'command':
            command_count += 1
    
    # Count active honeypots
    active_honeypots = len(running_honeypots)
    
    return {
        'totalAttacks': len(logs),
        'uniqueIPs': len(unique_ips),
        'activeHoneypots': active_honeypots,
        'commandsLogged': command_count,
        'protocolCounts': protocol_counts
    }

# API Routes

@app.route('/api/logs')
def get_logs():
    """Get all honeypot logs"""
    logs = get_all_logs()
    return jsonify(logs)

@app.route('/api/stats')
def get_stats():
    """Get statistics"""
    logs = get_all_logs()
    stats = calculate_stats(logs)
    return jsonify(stats)

@app.route('/api/configs')
def get_configs():
    """Get all honeypot configurations"""
    configs = {}
    protocols = ['telnet', 'ssh', 'http', 'mqtt', 'dnp3', 'coap', 'modbus']
    
    for protocol in protocols:
        config_file = CONFIGS_DIR / f'{protocol}_honeypot_config.json'
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    configs[protocol] = json.load(f)
            except:
                configs[protocol] = {}
        else:
            configs[protocol] = get_default_config(protocol)
    
    return jsonify(configs)

@app.route('/api/configs/<protocol>', methods=['GET', 'PUT'])
def handle_config(protocol):
    """Get or update a specific protocol configuration"""
    config_file = CONFIGS_DIR / f'{protocol}_honeypot_config.json'
    
    if request.method == 'GET':
        if config_file.exists():
            with open(config_file, 'r') as f:
                return jsonify(json.load(f))
        return jsonify(get_default_config(protocol))
    
    elif request.method == 'PUT':
        config_data = request.json
        CONFIGS_DIR.mkdir(exist_ok=True)
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
        return jsonify({'success': True})

@app.route('/api/status')
def get_status():
    """Get status of all honeypots"""
    return jsonify(running_honeypots)

@app.route('/api/honeypot/<protocol>/start', methods=['POST'])
def start_honeypot(protocol):
    """Start a honeypot"""
    if protocol in running_honeypots:
        return jsonify({'error': 'Honeypot already running'}), 400
    
    honeypot_script = HONEYPOTS_DIR / f'{protocol}.py'
    if not honeypot_script.exists():
        return jsonify({'error': 'Honeypot script not found'}), 404
    
    try:
        # Start the honeypot in a separate process
        process = subprocess.Popen(
            ['python3', str(honeypot_script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        running_honeypots[protocol] = True
        
        # Store process info for later stopping (in production, use proper process management)
        return jsonify({'success': True, 'message': f'{protocol} honeypot started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/honeypot/<protocol>/stop', methods=['POST'])
def stop_honeypot(protocol):
    """Stop a honeypot"""
    if protocol not in running_honeypots:
        return jsonify({'error': 'Honeypot not running'}), 400
    
    try:
        # In production, properly terminate the process
        # For now, just update status
        del running_honeypots[protocol]
        return jsonify({'success': True, 'message': f'{protocol} honeypot stopped'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_default_config(protocol):
    """Get default configuration for a protocol"""
    base_config = {
        'host': '0.0.0.0',
        'hostname': f'{protocol}-honeypot',
        'allow_all_logins': True,
        'log_directory': f'logs/{protocol}_honeypot_logs',
        'log_file': 'honeypot.log',
        'valid_credentials': {
            'admin': 'admin',
            'root': 'toor',
            'user': 'password'
        }
    }
    
    # Protocol-specific defaults
    port_map = {
        'telnet': 2323,
        'ssh': 2222,
        'http': 8080,
        'mqtt': 1883,
        'dnp3': 20000,
        'coap': 5683,
        'modbus': 502
    }
    
    base_config['port'] = port_map.get(protocol, 9999)
    
    if protocol in ['telnet', 'ssh']:
        base_config['banner'] = f'Welcome to {protocol.upper()} Server\n\n'
        base_config['filesystem'] = {
            '/': ['bin', 'etc', 'home', 'var', 'usr', 'tmp'],
            '/home': ['user'],
            '/home/user': ['documents', 'downloads', '.bash_history'],
            '/etc': ['passwd', 'shadow', 'hosts'],
            '/var': ['log', 'www'],
            '/tmp': []
        }
        base_config['files'] = {
            '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash',
            '/etc/hosts': '127.0.0.1 localhost\n192.168.1.1 router'
        }
    
    return base_config

# Serve React frontend
@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

if __name__ == '__main__':
    # Create necessary directories
    LOGS_DIR.mkdir(exist_ok=True)
    CONFIGS_DIR.mkdir(exist_ok=True)
    
    print("=" * 60)
    print("IoT Honeypot Management System")
    print("=" * 60)
    print(f"Dashboard: http://localhost:6000")
    print(f"API Base: http://localhost:6000/api")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=6000, debug=True)