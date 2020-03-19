import nmap


def run_nmap_scan(net_mask_slash_notation):
    nm = nmap.PortScanner()
    return nm.scan(hosts=net_mask_slash_notation, arguments='-O')['scan']

