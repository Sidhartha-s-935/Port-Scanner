from flask import Flask, request, render_template, jsonify
import nmap
import requests
import json
from concurrent.futures import *
import concurrent.futures
import threading

app = Flask(__name__)
IPAPI_API_KEY = '0d7a2d2fad44e48be68706d6dbc70be4'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    targets = request.form.get('targets')
    domain_name = request.form.get('domain')
    port_range = request.form.get('portRange')
    scan_type = request.form.get('scanType')

    targets_list = targets.split(",")
    scan_results = multi_threaded_scan(targets_list, port_range, scan_type)

    results = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_target = {executor.submit(scan_target, target, port_range, scan_type): target for target in targets_list}
        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]
            open_ports, geolocation_data = future.result()

            result = {
                'target': target,
                'open_ports': open_ports
            }

            result['geolocation'] = {
                'ip_address': geolocation_data.get('ip', 'Unknown'),
                'location': f"{geolocation_data.get('city', 'Unknown')}, {geolocation_data.get('region_name', 'Unknown')}, {geolocation_data.get('country_name', 'Unknown')}"
            }

            results.append(result)

    return jsonify(results)

def scan_target(target, port_range, scan_type):
    open_ports = perform_scan(target, port_range, scan_type)
    geolocation_data = get_geolocation(target)
    return open_ports, geolocation_data


def save_to_json(data, filename):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)
    print(f"Results saved to {filename}")

def multi_threaded_scan(targets, port_range, scan_type):
    results = []
    threads = []

    for target in targets:
        thread = threading.Thread(target=lambda: results.append((target, perform_scan(target, port_range, scan_type))))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return results

def perform_scan(target, port_range, scan_type):
    nm = nmap.PortScanner()
    nm.scan(target, arguments=f"-p {port_range} {scan_type}")  
    
    open_ports = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                state = nm[host][proto][port]['state']
                if state == 'open':
                    service_info = nm[host][proto][port].get('service', {}) 
                    open_ports.append((port, service_info))

    return open_ports

def get_geolocation(ip_address):
    response = requests.get(f"http://api.ipapi.com/{ip_address}?access_key={IPAPI_API_KEY}")
    data = response.json()
    return data

if __name__ == "__main__":
    app.run(debug=True)
