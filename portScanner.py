import socket
import requests
import argparse
from concurrent.futures import ThreadPoolExecutor

class CustomHelpFormatter(argparse.RawTextHelpFormatter):
    def _format_action(self, action):
        result = super()._format_action(action)
        result = result.lstrip()

        if action.help:
            result = result.replace("  ", " \t\t\t", 1)

        result += "\n"
        return result    

def detect_service(port):
    try:
        service = socket.getservbyport(port)
        return service
    except OSError:
        return "Unknown service"

def port_status_analysis(target, port, protocol='TCP'):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'TCP' else socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                return f"Port {port} is open (Service: {detect_service(port)})"
            elif result == 11: 
                return f"Port {port} is filtered (Service: {detect_service(port)})"
            else:
                return f"Port {port} is closed (Service: {detect_service(port)})"
    except Exception as e:
        return f"Error checking port {port}: {e}"

def geoip_lookup_online(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        return f"Location: {data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
    except Exception as e:
        return f"GeoIP lookup failed: {e}"

def generate_ports_from_range(port_range):
    start_port, end_port = port_range
    return list(range(start_port, end_port + 1))

def main(target, ports, protocol):
    print(f"\nScanning target: {target}")
    location_info = geoip_lookup_online(target)
    print(location_info)

    if not ports:
        print("No ports specified. Defaulting to common ports (22, 80, 443, 8080).")
        ports = [22, 80, 443, 8080] 

    expanded_ports = []
    for port in ports:
        if isinstance(port, str) and '-' in port:
            start_port, end_port = map(int, port.split('-'))
            expanded_ports.extend(generate_ports_from_range((start_port, end_port)))
        else:
            expanded_ports.append(int(port))

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(lambda port: port_status_analysis(target, port, protocol), expanded_ports)
        for result in results:
            print(result)

parser = argparse.ArgumentParser(
    description="Enhanced Port Scanner Tool with Service Detection and IP lookup. Author: d3v3sh225",
    formatter_class=CustomHelpFormatter,
    epilog="Examples:\n"
           "  python script.py 192.168.1.1\n"
           "  python script.py 192.168.1.1 -p 21 22 80 443 3306\n"
           "  python script.py 192.168.1.1 -p 22 80 443 --protocol TCP\n"
           "  python script.py 192.168.1.1 -p 20-80 --protocol UDP\n"
           "  python script.py example.com --protocol TCP\n"
)

parser.add_argument("target", help="Target IP or hostname")
parser.add_argument("-p", dest='ports', type=str, nargs='*', help="Specify ports to scan (can include ranges like 20-80)")
parser.add_argument("--protocol", choices=['TCP', 'UDP'], default='TCP', help="Choose protocol (default: TCP)")

args = parser.parse_args()

if not args.ports:
    args.ports = [21, 22, 53, 80, 443, 445, 8080]

ports = []
for p in args.ports:
    if isinstance(p, str) and '-' in p:
        ports.append(p)
    else:
        ports.append(int(p))

main(args.target, ports, args.protocol)
