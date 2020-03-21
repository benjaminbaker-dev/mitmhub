from socket import *
from scapy.all import *
import threading

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
    def __init__(self, target_mac, gateway_mac, my_mac, target_ip, interface):
        self.target_mac = target_mac
        self.gateway_mac = gateway_mac
        self.my_mac = my_mac
        self._scapy_socket = conf.L2socket(iface=interface, filter='host {}'.format(target_ip))
        self._should_forward = False
        self._forward_thread = None
        self._packet_filters = []
        self.target_ip = target_ip

    def add_filter(self, resolution_index, pkt_filter):
        """
        Add a filter at a given priority
        :param layer: The layer number to insert this rule at (must be one of the options in L2Tunnel.PARSE_CAPABLE_LAYERS)
        :param resolution_index: The index at which to insert the rule into the processing queue. Rules are resolved in
                                 the order of their resolution index, so a rule with a low resolution index is resolved
                                 before a rule with a high resolution index. If the resolution index is greater than the
                                 number of filters in the processing queue, then it is inserted at the end of the queue
        :param pkt_filter: A callable that expects a scapy packet, modifies it, and returns it modified
        :return: None
        """
        self._packet_filters.insert(resolution_index, pkt_filter)

    def repackage_frame(self, scapy_pkt):
        """
        Take a raw frame as scapy packet and change its MAC addresses according to the target and gateway mac addresses
        :param scapy_pkt: the raw frame as a scapy packet
        :return: a scapy packet object of the raw bytes of the new frame (changed mac addresses)
        """

        # if its coming from the gateway, its meant for the target
        if scapy_pkt[Ether].src == self.gateway_mac:
            scapy_pkt[Ether].src = self.my_mac
            scapy_pkt[Ether].dst = self.target_mac

        # if its coming from the target, its meant for the gateway
        elif scapy_pkt[Ether].src == self.target_mac:
            scapy_pkt[Ether].src = self.my_mac
            scapy_pkt[Ether].dst = self.gateway_mac

        return scapy_pkt

    def filter_layers(self, received_scapy_packet):
        """
        Take in raw data, parse it protocol layers, and apply this tunnel's protocol filters to each layer
        :param raw_data: The raw data of the frame (all data, including layer 2)
        :return: the raw bytes data of the disrupted frame
        """
        modified_packet = received_scapy_packet
        for pkt_filter in self._packet_filters:
            modified_packet = pkt_filter(modified_packet)
        return modified_packet


    def forward_loop(self):
        """
        A loop that receives raw frames and forwards them to their intended destinations
        :return: None
        """
        while self._should_forward:
            scapy_frame = self._scapy_socket.recv()

            # TODO: Replace this with a bpf on the socket itself
            if scapy_frame is None or IP not in scapy_frame:
                continue
            if scapy_frame[IP].src != self.target_ip and scapy_frame[IP].dst != self.target_ip:
                continue

            try:
                filtered_packet = self.filter_layers(scapy_frame)
            except DropPacketException:
                # some filter in filter_layers raised a drop packet exception, so drop this packet
                continue

            repackaged_frame = self.repackage_frame(filtered_packet)
            try:
                self._scapy_socket.send(repackaged_frame)
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
        :return: None
        """
        self._should_forward = False
        self._forward_thread.join()
        self._forward_thread = None
