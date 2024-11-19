import nmap
import json
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Function to get the actual local IP address
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except socket.error as e:
        print(f"Error getting local IP address: {e}")
        return None

# Function to get the local network CIDR (assuming a /24 subnet)
def get_local_network():
    local_ip = get_local_ip()
    if local_ip:
        return f"{local_ip}/24"
    return None

# Function to scan a single host and return its data
def scan_host(host):
    nm = nmap.PortScanner()
    host_info = {}

    try:
        nm.scan(hosts=host, arguments='-O -sV -T4 -A')
        host_info['hostnames'] = nm[host].hostnames() if nm[host].hostnames() else []
        host_info['status'] = nm[host].state()

        # Get OS details
        if 'osclass' in nm[host]:
            host_info['os'] = nm[host]['osclass']

        # Get open ports, services, and versions
        host_info['ports'] = []
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                port_info = nm[host][proto][port]
                host_info['ports'].append({
                    'port': port,
                    'service': port_info['name'],
                    'version': port_info.get('version', 'Unknown'),
                    'product': port_info.get('product', 'Unknown'),
                    'extrainfo': port_info.get('extrainfo', ''),
                    'state': port_info['state']
                })

        if 'vendor' in nm[host]:
            host_info['vendor'] = nm[host]['vendor']

        return host, host_info
    except Exception as e:
        print(f"Error scanning {host}: {e}")
        return host, None

# Real-time update of scan results to JSON file
def update_results_in_json(scan_results, filename='nmap_results.json'):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    data_to_save = {
        'timestamp': now,
        'scan_results': scan_results
    }

    # Save results to JSON file in real-time
    with open(filename, 'w') as f:
        json.dump(data_to_save, f, indent=4)
    print(f"Updated {filename} with new scan data.")

# Nmap scan function with real-time updates
def run_nmap_scan(targets, max_workers=10):
    nm = nmap.PortScanner()
    nm.scan(hosts=targets, arguments='-sn')  # Only ping to discover active hosts

    active_hosts = nm.all_hosts()
    total_hosts = len(active_hosts)
    scan_results = {}

    if total_hosts == 0:
        print("No active hosts found on the network.")
        return scan_results

    print(f"Found {total_hosts} active hosts. Starting detailed scan...")

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_host, host): host for host in active_hosts}
        completed_hosts = 0

        for future in as_completed(futures):
            host, host_info = future.result()
            if host_info:
                scan_results[host] = host_info
                completed_hosts += 1

                # Update JSON after every host scan
                update_results_in_json(scan_results)

            # Calculate ETA
            elapsed_time = time.time() - start_time
            avg_time_per_host = elapsed_time / (completed_hosts or 1)
            remaining_hosts = total_hosts - completed_hosts
            eta = avg_time_per_host * remaining_hosts

            print(f"[{completed_hosts}/{total_hosts}] Hosts scanned. ETA: {int(eta)} seconds remaining.")

    return scan_results

if __name__ == '__main__':
    network = get_local_network()
    if network:
        results = run_nmap_scan(network)
    else:
        print("Failed to detect local network.")
