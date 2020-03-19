import nmap

class InactiveHostException(Exception):
    pass

def run_detailed_scan(host):
    nm = nmap.PortScanner()
    scan = nm.scan(hosts=host, arguments='-O')['scan']
    if len(scan.keys()) == 0:
        raise InactiveHostException
    host_data = scan[host]
    os_names = [os['name'] for os in host_data['osmatch']] if len(host_data['osmatch']) > 0 else ['Unknown OS']
    host_names = [name['name'] for name in host_data['hostnames']] if len(host_data['hostnames']) > 0 else ['Unknown Name']

    tags = {
        'os_names':os_names,
        'host_names':host_names
    }
    return tags


def run_subnet_discovery(net_mask_slash_notation):
    nm = nmap.PortScanner()
    return nm.scan(hosts=net_mask_slash_notation, arguments='-sP')['scan']