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
        if UDP not in scapy_pkt or scapy_pkt[UDP].dport != dns_port:
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

def generate_tcp_disturbance(src_ip, new_payload):
    def disturb_tcp_packet(scapy_pkt):
        if TCP not in scapy_pkt or scapy_pkt[IP].src != src_ip:
            return scapy_pkt

        if len(bytes(scapy_pkt[TCP].payload)) == 0:
            return scapy_pkt

        payload_delta = len(new_payload) - len(bytes(scapy_pkt[TCP].payload))
        print(scapy_pkt[TCP].seq, len(scapy_pkt[TCP].payload))

        #scapy_pkt[TCP].seq += payload_delta
        scapy_pkt[TCP].chksum = 0
        scapy_pkt[TCP].payload = Raw(new_payload)

        scapy_pkt[IP].len += payload_delta
        scapy_pkt[IP].chksum = 0

        return scapy_pkt

    return ProtocolFilter(
        filter_function=disturb_tcp_packet,
        name='disturb_tcp',
        keyword_arguments={'src_ip':src_ip, 'new_payload': new_payload}
    )

def generate_http_replace_filter(domain_to_redirect, new_domain):
    HTTP_PORTS = (80, 8080)

    ip_to_redirect = socket.gethostbyname(domain_to_redirect)

    domain_to_redirect = domain_to_redirect.encode('ascii')
    new_domain = new_domain.encode('ascii')
    http_redirect_content = '\n'\
                            '<html>'\
                            '\n<head>'\
                            '\n<title>Moved</title>' \
                            '\n</head>'\
                            '\n<body>'\
                            '\n<h1>Moved</h1>'\
                            '\n<p>This page has moved to <a href="http://{new_domain}/">http://{new_domain}/</a>.</p>' \
                            '\n</body>' \
                            '\n</html>'.format(new_domain=new_domain.decode())
    http_redirect_header = 'HTTP/1.1 301 Moved Permanently\r\n'\
                            'Location: {new_domain}/\r\n'\
                            'Content-Type: text/html\r\n'\
                            'Content-Length: {content_length}\r\n'.format(new_domain=new_domain.decode(), content_length=len(http_redirect_content))
    http_redirect = http_redirect_header.encode() + http_redirect_content.encode()



    def static_http_rewrite(scapy_pkt):
        if TCP not in scapy_pkt:
            return scapy_pkt

        if scapy_pkt[TCP].sport not in HTTP_PORTS:
            return scapy_pkt

        http_payload = bytes(scapy_pkt[TCP].payload)
        if http_payload is None or len(http_payload) == 0:
            return scapy_pkt

        #if domain_to_redirect not in http_payload:
         #   return scapy_pkt

        original_payload_length = len(http_payload)

        payload_delta = len(http_redirect) - original_payload_length

        scapy_pkt[TCP].payload = Raw(http_redirect)
        print('{} + {}'.format(scapy_pkt[TCP].seq, payload_delta))
        #scapy_pkt[TCP].seq += payload_delta
        scapy_pkt[TCP].chksum = 0

        scapy_pkt[IP].len += payload_delta
        scapy_pkt[IP].chksum = 0
        #print('\nOriginal:', http_payload)
        #print('\nModified:', scapy_pkt[TCP].payload)
        #scapy_pkt.show()
        return scapy_pkt

    return ProtocolFilter(
        filter_function=static_http_rewrite,
        name='dynamic_http_domain_rewrite',
        keyword_arguments={'redirected_domain': domain_to_redirect, 'new_domain': new_domain}
    )
