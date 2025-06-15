import nmap

def scan_target(ip, ports="8080"):
    """
    Scansiona un host usando Nmap per identificare porte e servizi attivi.
    Di default scansiona solo la porta 8080, ma puoi passare altre porte o un range.
    """
    print(f"[scanner] Avvio scansione su {ip} sulla porta {ports}...")
    nm = nmap.PortScanner()

    try:
        # Scansione TCP solo sulle porte specificate
        nm.scan(hosts=ip, ports=ports, arguments='-sV -Pn')
        results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports_found = nm[host][proto].keys()
                for port in ports_found:
                    service = nm[host][proto][port]
                    results.append({
                        "ip": host,
                        "port": port,
                        "protocol": proto,
                        "name": service.get('name'),
                        "version": service.get('version'),
                        "product": service.get('product')
                    })
        return results

    except Exception as e:
        print(f"[scanner][errore] {e}")
        return []
