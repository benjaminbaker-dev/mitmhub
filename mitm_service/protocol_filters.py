from socket import inet_aton, inet_ntoa, IPPROTO_UDP, IPPROTO_TCP
from mitm_service.tunneler.tunneler import DropPacketException
from scapy.all import *
import dnslib
import time

DNS_PORT = 53

DNS_QUERY = 0
DNS_RESPONSE = 1

DNS_TYPE_IPV4 = 1
DNS_TYPE_IPV6 = 28

class InvalidStringFilter(Exception):
    """
    Exception to raise if string filter is invalid
    """
    pass

class ProtocolFilter:
    """
    Class to wrap the protocol filter functions so that we can remember the parameters they were constructed with
    """
    PARAM_EXPLANATION = {
        'redirect_ip_addresses': 'target_ip: Packets to this IP are redirected to the redirect_ip\n'
                                 'redirect_ip: Packets from target IP are redirected to this IP',
        'reassign_dns_resolution': 'domain_name: DNS responses to this domain name are reassigned to new_ip\n'
                                   'new_ip: DNS responses to domain_name are reassigned to this IP\n'
                                   'dns_port: The port to recognize DNS responses on. Defaults to 53',
        'log_dns_queries': 'log_file_name: The path to the file to log all DNS queries to\n'
                           'dns_port: The port to recognize DNS requests on. Defaults to 53',
        'drop_packets': 'string_filter: A filter that describes which packets to drop. A single filter is of\n'
                        '    the form <layer_name> <field_name> <comparator> <value>, where layer_name is\n'
                        '    the name of the scapy layer you want to filter, field name is the field whose\n'
                        '    value you want to filter by, comparator is either ==/!=, and value is the value\n'
                        '    you want to compare the layer/field to. Alternatively, a filter can just be the\n'
                        '    name of a layer, in which case the filter just checks for the existence of said\n'
                        '    layer. string_filter is any number of these single filters, seperated by "&&".\n'
                        '    The filter drops a packet only if each individual filter in string_filter is true',

    }

    def __init__(self, filter_function, name = None, keyword_arguments=None):
        """
        :param filter_function: the function to call. expects a scapy packet and returns a scapy packet
        :param name: the display name of the function
        :param keyword_arguments: the keyword arguments this function was called with
        """
        self.filter_function = filter_function
        self.name = name or ""
        self.keyword_arguments = keyword_arguments or {}

    def __call__(self, scapy_pkt):
        return self.filter_function(scapy_pkt)

    @property
    def param_explanation(self):
        if self.name in type(self).PARAM_EXPLANATION:
            return type(self).PARAM_EXPLANATION[self.name]
        return ""


class StringPacketFilter:
    @staticmethod
    def parse_string_filter(string_filter):
        """
        Parse a string filter into its individual filter parameters
        :param string_filter: string filters separated by  &&
        :return: List of [<layername>, <field_name>, <comparator>, <value>]" if valid, exception if not
        """
        individual_filters = string_filter.split('&&')
        parsed_filters = []
        for filter_string in individual_filters:
            filter_params = filter_string.split(" ")
            if len(filter_params) not in (1, 4):
                raise InvalidStringFilter(
                    "Invalid Filter: {}\nFilter should have <layername> (<field_name> <comparator> <value>)".format(
                        filter_string
                    ))
            if len(filter_params) == 4:
                layer_name, field_name, comparator, value = filter_params
                if comparator not in ('!=', '=='):
                    raise InvalidStringFilter('Comparator {} is invalid. Must be != or =='.format(comparator))
                parsed_filters.append((layer_name, field_name, comparator, value))
            else:
                layer_name, = filter_params
                parsed_filters.append((layer_name, ))
        return parsed_filters

    def __init__(self, string_filters):
        """
         Accepts a string filter and constructs an object that can identify if scapy packets match that filter
        :param string_filters: a list of strings of the form: "<layername> <field_name> <comparator> <value>" where:
            layername is a valid scapy layer (ex.: UDP, TCP, IP, Ether, etc.)
            field_name is a valid field for that layer (ex.: src, dst, sport, dport, etc.). Validity depends on the layername
            comparator is == or !=
            value is the value to check
            A filter can also just be a layer name, in which case, the filter just checks for the existence of that layer
            Each individual filter is seperated by "&&"
        """
        self.string_filters = type(self).parse_string_filter(string_filters)

    def does_packet_match(self, scapy_pkt):
        for filter_params in self.string_filters:
            layer_name = filter_params[0]
            layer = scapy_pkt.getlayer(layer_name)
            if layer is None:
                return False
            if len(filter_params) == 4:
                field_name, comparator, value = filter_params[1:]
                try:
                    actual_value = layer.getfieldval(field_name)
                except AttributeError:
                    return False
                if comparator == '==' and str(actual_value) != value:
                    return False
                elif comparator == '!=' and str(actual_value) == value:
                    return False
        return True



def generate_ip_redirect_rule(target_ip, redirect_ip):
    """
    Factory function to generate a filter that swaps ips
    :param target_ip: the dest ip to swap from
    :param redirect_ip: the source ip to swap to
    :return: a filter function callable (takes a scapy packet, returns a scapy packet)
    """

    def disrupt_ip_traffic(scapy_pkt):
        if IP not in scapy_pkt:
            # not an ip packet so ignore
            return scapy_pkt

        ip_header = scapy_pkt[IP]
        if ip_header.dst != target_ip and ip_header.src != redirect_ip:
            return scapy_pkt

        if ip_header.dst == target_ip:
            print('Redirecting packet meant for {} to {}'.format(ip_header.dst_ip_str, inet_ntoa(redirect_ip)))
            ip_header.dst = redirect_ip

        elif ip_header.src == redirect_ip:
            print('Spoofing packet origin from {} to {}'.format(ip_header.src_ip_str, inet_ntoa(target_ip)))
            ip_header.src = target_ip

        return scapy_pkt

    return ProtocolFilter(
        filter_function=disrupt_ip_traffic,
        name='redirect_ip_addresses',
        keyword_arguments={
            'target_ip': target_ip,
            'redirect_ip': redirect_ip
        })


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
        if UDP not in scapy_pkt or str(scapy_pkt[UDP].sport) != str(dns_port):
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

    return ProtocolFilter(
        filter_function=disrupt_dns_traffic,
        name='reassign_dns_resolution',
        keyword_arguments={
            'domain_name': domain_name,
            'new_ip': new_ip,
            'dns_port': dns_port
        })


def generate_dns_log_rule(log_file_name, dns_port=DNS_PORT):
    """
    Factory function to generate filters that log all dns queries
    :param log_file_object: The file object (writeable) to log the queries to
    :return: the filter function
    """

    def log_dns_queries(scapy_pkt):
        if UDP not in scapy_pkt or str(scapy_pkt[UDP].dport) != str(dns_port):
            return scapy_pkt

        udp_payload = bytes(scapy_pkt[UDP].payload)

        record = dnslib.DNSRecord.parse(udp_payload)
        if record.header.qr != DNS_QUERY:
            return scapy_pkt

        first_question = record.get_q()
        with open(log_file_name, 'a') as log_file:
            log_file.write('{}:\t{} asked for {}\n'.format(
                time.ctime(),
                scapy_pkt[IP].src,
                str(first_question.get_qname())
            ))

        return scapy_pkt

    return ProtocolFilter(
        filter_function=log_dns_queries,
        name='log_dns_queries',
        keyword_arguments={
            'log_file_name': log_file_name,
            'dns_port': dns_port
        })


def generate_packet_drop_rule(filter_string):
    string_filterer = StringPacketFilter(filter_string)

    def drop_packet(scapy_packet):
        if string_filterer.does_packet_match(scapy_packet):
            raise DropPacketException
        else:
            return scapy_packet

    return ProtocolFilter(
        filter_function=drop_packet,
        name='drop_packets',
        keyword_arguments={'filter_string':filter_string}
    )
