from socket import inet_aton, inet_ntoa, IPPROTO_UDP, IPPROTO_TCP
from tunneler.network_headers import TcpHeader, UdpHeader, IpHeader
import dnslib

DNS_PORT = 53

DNS_QUERY = 0
DNS_RESPONSE = 1

DNS_TYPE_IPV4 = 1
DNS_TYPE_IPV6 = 28

def redirect_ips(target_ip, redirect_ip):
    """
    Factory function to generate a disruption rule that swaps ips
    :param target_ip: the dest ip to swap from
    :param redirect_ip: the source ip to swap to
    :return: a disruption rule function (takes a header and payload, returns a header and payload)
    """
    target_ip = inet_aton(target_ip)
    redirect_ip = inet_aton(redirect_ip)

    def disrupt_ip_traffic(ip_header, ip_payload):
        if not isinstance(ip_header, IpHeader):
            #not an ip packet so ignore
            return ip_header, ip_payload

        if ip_header.dst_ip != target_ip and ip_header.src_ip != redirect_ip:
            return ip_header, ip_payload

        if ip_header.dst_ip == target_ip:
            print('Redirecting packet meant for {} to {}'.format(ip_header.dst_ip_str, inet_ntoa(redirect_ip)))
            ip_header.dst_ip = redirect_ip

        elif ip_header.src_ip == redirect_ip:
            print('Spoofing packet origin from {} to {}'.format(ip_header.src_ip_str, inet_ntoa(target_ip)))
            ip_header.src_ip = target_ip



        #adjust checksums, if they exist
        if ip_header.proto == IPPROTO_TCP:
            l4_header = TcpHeader.parse_header(ip_payload[:TcpHeader.DEFAULT_TCP_HEADER_SIZE])
        elif ip_header.proto == IPPROTO_UDP:
            l4_header = UdpHeader.parse_header(ip_payload[:UdpHeader.UDP_HEADER_SIZE])
        else:
            return ip_header, ip_payload
        l4_payload = ip_payload[l4_header.length():]
        l4_header.checksum = 0
        ip_payload = l4_header.get_raw_header() + l4_payload

        return ip_header, ip_payload

    return disrupt_ip_traffic


def change_dns_responses(domain_name, new_ip):
    """

    :param domain_name:
    :param new_ip:
    :return:
    """
    domain_name = dnslib.DNSLabel(domain_name)
    new_ip = dnslib.dns.A(new_ip)

    def disrupt_dns_traffic(udp_header, udp_payload):
        if not isinstance(udp_header, UdpHeader) or udp_header.src_port != DNS_PORT:
            return udp_header, udp_payload

        record = dnslib.DNSRecord.parse(udp_payload)
        if record.header.qr != DNS_RESPONSE:
            return udp_header, udp_payload
        answers = record.rr

        for answer in answers:
            if answer.rtype != DNS_TYPE_IPV4:
                continue
            if answer.get_rname() == domain_name:
                print('Redirecting response from {}/{} to {}...'.format(answer.get_rname(), answer.rdata, new_ip))
                answer.rdata = new_ip
        udp_payload = record.pack()
        udp_header.checksum = 0

        return udp_header, udp_payload

    return disrupt_dns_traffic


