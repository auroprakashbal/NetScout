import socket
import concurrent.futures
import ipaddress
from datetime import datetime
from vuln_db import VULN_DB, RISK_SCORE

# Most commonly targeted ports
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 512, 513, 514, 587, 631, 993, 995,
    1080, 1433, 1521, 2049, 2181, 3000, 3306, 3389,
    4444, 5432, 5900, 6379, 7001, 8000, 8080, 8443,
    8888, 9200, 9300, 10000, 11211, 27017, 27018, 50000
]


def check_port(ip, port, timeout=1):
    """Check if a single TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def grab_banner(ip, port, timeout=2):
    """Try to grab a service banner from an open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        # Send HTTP probe for web ports, otherwise just read
        if port in [80, 8080, 8000, 8888, 3000]:
            sock.send(b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n')
        banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
        sock.close()
        # Return first line only (cleaner)
        return banner.split('\n')[0][:120] if banner else ''
    except Exception:
        return ''


def resolve_hostname(ip):
    """Try to resolve IP to hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def get_service_name(port):
    """Get service name for a port."""
    try:
        return socket.getservbyport(port, 'tcp').upper()
    except Exception:
        return VULN_DB.get(port, {}).get('service', f'PORT-{port}')


def scan_host(ip):
    """
    Scan a single host: discover open ports, detect services,
    and assess vulnerabilities.
    Returns a dict with all findings, or None if host is down.
    """
    open_ports = []

    # Scan all common ports concurrently (faster)
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as executor:
        futures = {executor.submit(check_port, ip, port): port for port in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass

    # If no ports found, host is likely down or firewalled
    if not open_ports:
        return None

    # For each open port, get service info and vulnerability data
    port_details = []
    for port in sorted(open_ports):
        banner = grab_banner(ip, port)
        vuln_info = VULN_DB.get(port, None)

        if vuln_info:
            service  = vuln_info['service']
            risk     = vuln_info['risk']
            desc     = vuln_info['description']
            vulns    = vuln_info['vulnerabilities']
            cves     = vuln_info['cves']
        else:
            service  = get_service_name(port)
            risk     = 'INFO'
            desc     = 'No specific vulnerability data for this port. Verify if this service should be exposed.'
            vulns    = ['Port is open and accessible from the network']
            cves     = []

        port_details.append({
            'port':            port,
            'service':         service,
            'banner':          banner,
            'risk':            risk,
            'description':     desc,
            'vulnerabilities': vulns,
            'cves':            cves,
            'risk_score':      RISK_SCORE.get(risk, 0)
        })

    hostname = resolve_hostname(ip)

    # Count findings by risk level
    risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for p in port_details:
        risk_counts[p['risk']] = risk_counts.get(p['risk'], 0) + 1

    # Overall host risk = worst single finding
    overall_risk = 'INFO'
    for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if risk_counts[level] > 0:
            overall_risk = level
            break

    # Host risk score (0–100)
    raw_score = sum(RISK_SCORE.get(p['risk'], 0) for p in port_details)
    host_score = min(100, raw_score * 3)

    return {
        'ip':           ip,
        'hostname':     hostname or ip,
        'open_ports':   len(open_ports),
        'ports':        port_details,
        'risk_counts':  risk_counts,
        'overall_risk': overall_risk,
        'host_score':   host_score,
        'scanned_at':   datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }


class NetworkScanner:
    """Main scanner class. Accepts single IPs, hostnames, or CIDR ranges."""

    def parse_target(self, target):
        """Return list of IP strings to scan."""
        target = target.strip()
        hosts = []

        # Try CIDR range (e.g. 192.168.1.0/24)
        try:
            network = ipaddress.ip_network(target, strict=False)
            host_list = list(network.hosts())
            if len(host_list) > 254:
                host_list = host_list[:254]   # cap at /24 for performance
            return [str(ip) for ip in host_list]
        except ValueError:
            pass

        # Try single IP
        try:
            ipaddress.ip_address(target)
            return [target]
        except ValueError:
            pass

        # Try hostname (resolve to IP)
        try:
            ip = socket.gethostbyname(target)
            return [ip]
        except Exception:
            pass

        return []

    def scan(self, target):
        """
        Run a full scan against the target and return structured results.
        """
        hosts_to_scan = self.parse_target(target)

        results = {
            'target':    target,
            'started':   datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'hosts':     [],
            'summary': {
                'total_scanned': len(hosts_to_scan),
                'hosts_up':      0,
                'total_ports':   0,
                'risk_counts':   {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0},
                'risk_score':    0,
                'overall_risk':  'INFO'
            },
            'error': None
        }

        if not hosts_to_scan:
            results['error'] = f'Could not resolve or parse target: {target}'
            return results

        for ip in hosts_to_scan:
            host_result = scan_host(ip)
            if host_result:
                results['hosts'].append(host_result)
                results['summary']['hosts_up']    += 1
                results['summary']['total_ports'] += host_result['open_ports']
                for lvl, cnt in host_result['risk_counts'].items():
                    results['summary']['risk_counts'][lvl] += cnt

        # Final risk score
        rc = results['summary']['risk_counts']
        score = (rc['CRITICAL'] * 25) + (rc['HIGH'] * 10) + (rc['MEDIUM'] * 4) + (rc['LOW'] * 1)
        results['summary']['risk_score'] = min(100, score)

        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if rc[level] > 0:
                results['summary']['overall_risk'] = level
                break

        results['finished'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return results
