from socket import *
import threading
from mitm_service.tunneler.network_headers import *

L3_PROTO_IP = 0x0800
MAX_BUF_SIZE = 0xffffffff


class TunnelException(Exception):
    pass


class BadLayerException(TunnelException):
    pass

class DropPacketException(TunnelException):
    """
    An exception for a rule to raise when it wants to drop a packet entirely
    """
    pass


def _create_raw_ip_socket(interface):
    """
    Create a raw socket to listen for ip packets on a specific interface
    :param interface: the interface for the created socket to listen on
    :return: a socket object
    NOTE: the socket will receive the layer 2 and 3 headers, in addition to the payload
    """
    raw_sock = socket(AF_PACKET, SOCK_RAW, L3_PROTO_IP)
    raw_sock.bind((interface, L3_PROTO_IP))

    return raw_sock

class L2Tunnel:
    """
    A class for handling tunnel forwarding on layer 2
    """
    DISRUPTION_CAPABLE_LAYERS = [2, 3, 4]

    PARSE_L4_FUNCTIONS = {
        IPPROTO_UDP: UdpHeader.parse_raw_header,
        IPPROTO_TCP: TcpHeader.parse_raw_header,
    }

    def __init__(self, target_mac, gateway_mac, my_mac, target_ip, interface):
        self.target_mac = target_mac
        self.gateway_mac = gateway_mac
        self.my_mac = my_mac
        self._raw_sock = _create_raw_ip_socket(interface)
        self._should_forward = False
        self._forward_thread = None
        self._disruption_rules = {}
        self.target_ip = inet_aton(target_ip)
        for layer_num in type(self).DISRUPTION_CAPABLE_LAYERS:
            self._disruption_rules[layer_num] = lambda header, payload: (header, payload)

    def add_disruption_rule(self, layer, rule):
        """
        Add a disruption rule at the given layer
        :param layer: The layer number to insert this rule at (must be one of the options in L2Tunnel.PARSE_CAPABLE_LAYERS)
        :param rule: A lambda that excepts this layer's header and payload, modifies them, and returns them modified
        :return: None
        """
        if layer not in type(self).DISRUPTION_CAPABLE_LAYERS:
            raise BadLayerException('This tunnel does not support disruption on layer {} (only on layers {})'.format(
                layer,
                type(self).DISRUPTION_CAPABLE_LAYERS
            ))

        self._disruption_rules[layer] = rule

    def repackage_frame(self, raw_frame):
        """
        Take a raw frame as bytes and change its MAC addresses according to the target and gateway mac addresses
        :param raw_frame: the raw frame as bytes
        :return: a bytes object of the raw bytes of the new frame (changed mac addresses)
        """
        raw_ether_header = raw_frame[:EtherHeader.TOTAL_HEADER_LEN]
        parsed_ether_header, ether_header_len = EtherHeader.parse_raw_header(raw_ether_header)

        # if its coming from the gateway, its meant for the target
        if parsed_ether_header.src_addr == self.gateway_mac:
            parsed_ether_header.src_addr = self.my_mac
            parsed_ether_header.dst_addr = self.target_mac

        # if its coming from the target, its meant for the gateway
        elif parsed_ether_header.src_addr == self.target_mac:
            parsed_ether_header.src_addr = self.my_mac
            parsed_ether_header.dst_addr = self.gateway_mac

        return parsed_ether_header.get_raw_header() + raw_frame[EtherHeader.TOTAL_HEADER_LEN:]

    def disrupt_layers(self, raw_data):
        """
        Take in raw data, parse it protocol layers, and apply this tunnel's service disruption rules to each layer
        :param raw_data: The raw data of the frame (all data, including layer 2)
        :return: the raw bytes data of the disrupted frame
        """
        # receive and disrupt l2
        recv_etherheader, recv_etherheader_len = EtherHeader.parse_raw_header(raw_data[:EtherHeader.TOTAL_HEADER_LEN])
        l2_payload = raw_data[recv_etherheader_len:]
        recv_etherheader, l2_payload = self._disruption_rules[2](recv_etherheader, l2_payload)

        # receive and disrupt l3
        raw_ip_header = l2_payload[:IpHeader.DEFAULT_HEADER_SIZE]
        recv_ipheader, ip_header_len = IpHeader.parse_raw_header(raw_ip_header)
        l3_payload = l2_payload[ip_header_len:]
        recv_ipheader, l3_payload = self._disruption_rules[3](recv_ipheader, l3_payload)

        # receive and disrupt l4
        if recv_ipheader.proto in type(self).PARSE_L4_FUNCTIONS:
            recv_l4_header, l4_header_len = type(self).PARSE_L4_FUNCTIONS[recv_ipheader.proto](l3_payload)
        else:
            recv_l4_header, l4_header_len = UnknownProtocol.parse_raw_header(l3_payload)

        # add the pseudo header bytes to the l4 header object, this doesnt happen in the parse because the parse doesnt
        # see the necessary l3 info
        pseudo_header = generate_pseudo_header(
            recv_ipheader.src_ip,
            recv_ipheader.dst_ip,
            recv_ipheader.proto,
            recv_ipheader.tot_len
        )
        recv_l4_header.pseudo_header = pseudo_header

        l4_payload = l3_payload[l4_header_len:]
        recv_l4_header, l4_payload = self._disruption_rules[4](recv_l4_header, l4_payload)

        # recalculate ip checksum
        recv_ipheader.fill_payload_dependent_fields(recv_l4_header.get_raw_header()+l4_payload)

        raw_packet_data = b''
        raw_packet_data += recv_etherheader.get_raw_header()
        raw_packet_data += recv_ipheader.get_raw_header()
        raw_packet_data += recv_l4_header.get_raw_header()
        raw_packet_data += l4_payload

        return raw_packet_data

    def forward_loop(self):
        """
        A loop that receives raw frames and forwards them to their intended destinations
        :return: None
        """
        while self._should_forward:
            data, addr = self._raw_sock.recvfrom(MAX_BUF_SIZE)

            # TODO: figure out what x y and z are
            recv_iface, x, y, z, src_mac_addr = addr

            # TODO: Replace this with a bpf on the socket itself
            recv_ipheader, recv_ipheader_len = IpHeader.parse_raw_header(data[EtherHeader.TOTAL_HEADER_LEN:])
            if recv_ipheader.dst_ip != self.target_ip and recv_ipheader.src_ip != self.target_ip:
                continue

            try:
                disrupted_packet = self.disrupt_layers(data)
            except DropPacketException:
                # some filter in disrupt_layers raised a drop packet exception, so drop this packet
                continue

            repackaged_frame = self.repackage_frame(disrupted_packet)
            try:
                self._raw_sock.sendto(repackaged_frame, (recv_iface, x, y, z, self.my_mac))
            except OSError:
                # usually means the frame was too long to send, best effort, so ignore it and move on
                pass

    def start_forward_thread(self):
        """
        Start this tunnel's forward_loop in a different thread, and signal that thread to start
        :return: None
        """
        self._forward_thread = threading.Thread(target=self.forward_loop, args=())
        self._should_forward = True
        self._forward_thread.start()

    def stop_forward_thread(self):
        """
        Signal this tunnel's forward thread to stop and wait for it to join
        :return:
        """
        self._should_forward = False
        self._forward_thread.join()
        self._forward_thread = None

