import socket
import threading
import subprocess
import json
import time
import ipaddress
import requests
from datetime import datetime
import nmap
import os
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

class NetworkScanner:
    def __init__(self):
        self.discovered_devices = {}
        self.scan_results_file = "network_scan_results.json"
        self.vulnerability_db_file = "vulnerability_db.json"
        self.nm = nmap.PortScanner()
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        
    def get_local_network(self):
        """Get the local network CIDR"""
        try:
            # Get default gateway
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'IPv4 Address' in line:
                        ip = line.split(':')[1].strip()
                        # Assume /24 subnet for simplicity
                        network = '.'.join(ip.split('.')[:-1]) + '.0/24'
                        return network
            else:
                # Linux/Mac
                result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
                if result.returncode == 0:
                    gateway = result.stdout.split()[2]
                    # Get network from gateway
                    network = '.'.join(gateway.split('.')[:-1]) + '.0/24'
                    return network
                else:
                    # Fallback method
                    hostname = socket.gethostname()
                    local_ip = socket.gethostbyname(hostname)
                    network = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
                    return network
        except Exception as e:
            print(f"Error getting local network: {e}")
            return "192.168.1.0/24"  # Default fallback
    
    def ping_host(self, ip):
        """Ping a single host to check if it's alive"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                      capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, text=True, timeout=5)
                return result.returncode == 0
        except Exception:
            return False
    
    def get_hostname(self, ip):
        """Get hostname for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return "Unknown"
    
    def get_mac_address(self, ip):
        """Get MAC address for an IP (works best on local network)"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                mac = parts[1]
                                if '-' in mac and len(mac) == 17:
                                    return mac.replace('-', ':')
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                mac = parts[2]
                                if ':' in mac and len(mac) == 17:
                                    return mac
        except Exception:
            pass
        return "Unknown"
    
    def scan_ports(self, ip, ports=None):
        """Scan common ports on a host"""
        if ports is None:
            ports = self.common_ports
        
        open_ports = []
        services = {}
        
        try:
            # Use nmap for more accurate scanning
            nm_scan = self.nm.scan(ip, arguments=f'-p {",".join(map(str, ports))} -sV --version-intensity 3')
            
            if ip in nm_scan['scan']:
                host_info = nm_scan['scan'][ip]
                if 'tcp' in host_info:
                    for port, port_info in host_info['tcp'].items():
                        if port_info['state'] == 'open':
                            open_ports.append(port)
                            service_name = port_info.get('name', 'unknown')
                            service_version = port_info.get('version', '')
                            services[port] = {
                                'service': service_name,
                                'version': service_version,
                                'product': port_info.get('product', ''),
                                'extrainfo': port_info.get('extrainfo', '')
                            }
        except Exception as e:
            # Fallback to basic socket scanning
            print(f"Nmap scan failed for {ip}, using socket scan: {e}")
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                        services[port] = {'service': 'unknown', 'version': ''}
                    sock.close()
                except Exception:
                    continue
        
        return open_ports, services
    
    def detect_os(self, ip):
        """Attempt to detect operating system"""
        try:
            nm_scan = self.nm.scan(ip, arguments='-O')
            if ip in nm_scan['scan'] and 'osmatch' in nm_scan['scan'][ip]:
                osmatch = nm_scan['scan'][ip]['osmatch']
                if osmatch:
                    return osmatch[0]['name']
        except Exception:
            pass
        return "Unknown"
    
    def check_vulnerabilities(self, ip, services):
        """Check for known vulnerabilities based on services"""
        vulnerabilities = []
        
        # Load vulnerability database
        vuln_db = self.load_vulnerability_db()
        
        for port, service_info in services.items():
            service = service_info.get('service', '')
            version = service_info.get('version', '')
            
            # Check for common vulnerabilities
            if port == 21 and 'ftp' in service.lower():
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'vulnerability': 'Anonymous FTP access may be enabled',
                    'severity': 'Medium',
                    'recommendation': 'Disable anonymous FTP access'
                })
            
            if port == 23 and 'telnet' in service.lower():
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'vulnerability': 'Telnet is insecure (plaintext)',
                    'severity': 'High',
                    'recommendation': 'Use SSH instead of Telnet'
                })
            
            if port == 80 and not any(p in services for p in [443]):
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'vulnerability': 'HTTP without HTTPS encryption',
                    'severity': 'Medium',
                    'recommendation': 'Implement HTTPS encryption'
                })
            
            if port == 135 and platform.system() == "Windows":
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'vulnerability': 'Windows RPC endpoint mapper exposed',
                    'severity': 'Medium',
                    'recommendation': 'Restrict access to RPC services'
                })
            
            if port == 3389:
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'vulnerability': 'RDP service exposed to network',
                    'severity': 'High',
                    'recommendation': 'Use VPN or restrict RDP access'
                })
        
        return vulnerabilities
    
    def load_vulnerability_db(self):
        """Load vulnerability database"""
        try:
            if os.path.exists(self.vulnerability_db_file):
                with open(self.vulnerability_db_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        
        # Default vulnerability patterns
        return {
            'services': {
                'ftp': ['anonymous_access', 'weak_authentication'],
                'telnet': ['plaintext_protocol'],
                'http': ['no_encryption', 'default_credentials'],
                'ssh': ['weak_ciphers', 'default_credentials'],
                'rdp': ['exposed_service', 'weak_authentication']
            }
        }
    
    def scan_single_host(self, ip):
        """Scan a single host comprehensively"""
        print(f"Scanning {ip}...")
        
        if not self.ping_host(ip):
            return None
        
        hostname = self.get_hostname(ip)
        mac_address = self.get_mac_address(ip)
        open_ports, services = self.scan_ports(ip)
        os_info = self.detect_os(ip)
        vulnerabilities = self.check_vulnerabilities(ip, services)
        
        device_info = {
            'ip': ip,
            'hostname': hostname,
            'mac_address': mac_address,
            'os': os_info,
            'open_ports': open_ports,
            'services': services,
            'vulnerabilities': vulnerabilities,
            'scan_time': datetime.now().isoformat(),
            'status': 'online'
        }
        
        return device_info
    
    def network_discovery_scan(self, network=None, max_threads=50):
        """Perform network discovery scan"""
        if network is None:
            network = self.get_local_network()
        
        print(f"Starting network discovery scan on {network}")
        
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())
        except Exception as e:
            print(f"Error parsing network: {e}")
            return {}
        
        discovered_devices = {}
        
        # Use ThreadPoolExecutor for parallel scanning
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all scanning tasks
            future_to_ip = {executor.submit(self.scan_single_host, str(ip)): str(ip) 
                           for ip in hosts}
            
            # Collect results as they complete
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result(timeout=30)
                    if result:
                        discovered_devices[ip] = result
                        print(f"✓ Found device: {ip} ({result['hostname']})")
                except Exception as e:
                    print(f"✗ Error scanning {ip}: {e}")
        
        self.discovered_devices = discovered_devices
        self.save_scan_results()
        
        return discovered_devices
    
    def quick_network_discovery(self, network=None):
        """Quick network discovery using ping only"""
        if network is None:
            network = self.get_local_network()
        
        print(f"Starting quick network discovery on {network}")
        
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())
        except Exception as e:
            print(f"Error parsing network: {e}")
            return {}
        
        online_hosts = []
        
        # Quick ping scan
        with ThreadPoolExecutor(max_workers=100) as executor:
            future_to_ip = {executor.submit(self.ping_host, str(ip)): str(ip) 
                           for ip in hosts}
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    if future.result(timeout=5):
                        online_hosts.append(ip)
                        print(f"✓ Host online: {ip}")
                except Exception as e:
                    print(f"✗ Error pinging {ip}: {e}")
        
        # Get basic info for online hosts
        quick_results = {}
        for ip in online_hosts:
            quick_results[ip] = {
                'ip': ip,
                'hostname': self.get_hostname(ip),
                'mac_address': self.get_mac_address(ip),
                'status': 'online',
                'scan_time': datetime.now().isoformat(),
                'scan_type': 'quick'
            }
        
        return quick_results
    
    def targeted_port_scan(self, ip, ports):
        """Perform targeted port scan on specific IP"""
        print(f"Performing targeted port scan on {ip}")
        
        if not self.ping_host(ip):
            return None
        
        open_ports, services = self.scan_ports(ip, ports)
        vulnerabilities = self.check_vulnerabilities(ip, services)
        
        result = {
            'ip': ip,
            'hostname': self.get_hostname(ip),
            'open_ports': open_ports,
            'services': services,
            'vulnerabilities': vulnerabilities,
            'scan_time': datetime.now().isoformat(),
            'scan_type': 'targeted'
        }
        
        return result
    
    def save_scan_results(self):
        """Save scan results to file"""
        try:
            scan_data = {
                'scan_time': datetime.now().isoformat(),
                'devices': self.discovered_devices
            }
            
            with open(self.scan_results_file, 'w') as f:
                json.dump(scan_data, f, indent=2)
            
            print(f"Scan results saved to {self.scan_results_file}")
        except Exception as e:
            print(f"Error saving scan results: {e}")
    
    def load_scan_results(self):
        """Load previous scan results"""
        try:
            if os.path.exists(self.scan_results_file):
                with open(self.scan_results_file, 'r') as f:
                    data = json.load(f)
                    self.discovered_devices = data.get('devices', {})
                    return data
        except Exception as e:
            print(f"Error loading scan results: {e}")
        
        return {'devices': {}, 'scan_time': None}
    
    def get_network_statistics(self):
        """Get network scanning statistics"""
        if not self.discovered_devices:
            self.load_scan_results()
        
        total_devices = len(self.discovered_devices)
        vulnerable_devices = sum(1 for device in self.discovered_devices.values() 
                               if device.get('vulnerabilities'))
        
        # Count services
        service_count = {}
        port_count = {}
        os_count = {}
        
        for device in self.discovered_devices.values():
            # Count services
            for port, service_info in device.get('services', {}).items():
                service = service_info.get('service', 'unknown')
                service_count[service] = service_count.get(service, 0) + 1
            
            # Count ports
            for port in device.get('open_ports', []):
                port_count[port] = port_count.get(port, 0) + 1
            
            # Count OS
            os_info = device.get('os', 'Unknown')
            os_count[os_info] = os_count.get(os_info, 0) + 1
        
        return {
            'total_devices': total_devices,
            'vulnerable_devices': vulnerable_devices,
            'service_distribution': service_count,
            'port_distribution': port_count,
            'os_distribution': os_count,
            'scan_time': max([device.get('scan_time', '') for device in self.discovered_devices.values()] or [''])
        }
    
    def export_results_csv(self, filename="network_scan_results.csv"):
        """Export scan results to CSV"""
        try:
            import csv
            
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['IP', 'Hostname', 'MAC', 'OS', 'Open Ports', 'Services', 'Vulnerabilities', 'Scan Time']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for device in self.discovered_devices.values():
                    writer.writerow({
                        'IP': device.get('ip', ''),
                        'Hostname': device.get('hostname', ''),
                        'MAC': device.get('mac_address', ''),
                        'OS': device.get('os', ''),
                        'Open Ports': ', '.join(map(str, device.get('open_ports', []))),
                        'Services': ', '.join([f"{port}:{info.get('service', 'unknown')}" 
                                             for port, info in device.get('services', {}).items()]),
                        'Vulnerabilities': len(device.get('vulnerabilities', [])),
                        'Scan Time': device.get('scan_time', '')
                    })
            
            print(f"Results exported to {filename}")
            return filename
        except Exception as e:
            print(f"Error exporting to CSV: {e}")
            return None

# Example usage and testing
if __name__ == "__main__":
    scanner = NetworkScanner()
    
    # Quick network discovery
    print("=== Quick Network Discovery ===")
    quick_results = scanner.quick_network_discovery()
    print(f"Found {len(quick_results)} online devices")
    
    # Full network scan (comment out for quick testing)
    # print("\n=== Full Network Scan ===")
    # full_results = scanner.network_discovery_scan()
    # print(f"Scanned {len(full_results)} devices")
    
    # Get statistics
    print("\n=== Network Statistics ===")    
    stats = scanner.get_network_statistics()
    print(f"Total devices: {stats['total_devices']}")
    print(f"Vulnerable devices: {stats['vulnerable_devices']}")
    
    # Export results
    # scanner.export_results_csv()