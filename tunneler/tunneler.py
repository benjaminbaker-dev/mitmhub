from socket import *
from tunneler.network_headers import EtherHeader, IpHeader
import threading

L3_PROTO_IP = 0x0800
MAX_BUF_SIZE = 0xffffffff


def create_raw_ip_socket(interface):
    raw_sock = socket(AF_PACKET, SOCK_RAW, L3_PROTO_IP)
    #raw_sock.setsockopt(SOL_SOCKET, SO_RCVBUF, MAX_BUF_SIZE)

    raw_sock.bind((interface, L3_PROTO_IP))

    return raw_sock

class L2Tunnel:
    def __init__(self, target_mac, gateway_mac, my_mac, interface):
        self.target_mac = target_mac
        self.gateway_mac = gateway_mac
        self.my_mac = my_mac
        self.raw_sock = create_raw_ip_socket(interface)
        self.should_forward = False
        self.forward_thread = threading.Thread(target=self.forward_loop, args = ())

    def repackage_frame(self, raw_frame):
        raw_ether_header = raw_frame[:EtherHeader.TOTAL_HEADER_LEN]
        parsed_ether_header = EtherHeader.parse_header(raw_ether_header)

        # if its coming from the gateway, its meant for the target
        if parsed_ether_header.src_addr == self.gateway_mac:
            parsed_ether_header.src_addr = self.my_mac
            parsed_ether_header.dst_addr = self.target_mac

        # if its coming from the target, its meant for the gateway
        elif parsed_ether_header.src_addr == self.target_mac:
            parsed_ether_header.src_addr = self.my_mac
            parsed_ether_header.dst_addr = self.gateway_mac

        return parsed_ether_header.get_raw_header() + raw_frame[EtherHeader.TOTAL_HEADER_LEN:]

    def forward_loop(self):
        while self.should_forward:
            data, addr = self.raw_sock.recvfrom(MAX_BUF_SIZE)
            recv_iface, x, y, z, src_mac_addr = addr
            recv_etherheader = EtherHeader.parse_header(data[:EtherHeader.TOTAL_HEADER_LEN])
            if recv_etherheader.src_addr not in (self.gateway_mac, self.target_mac):
                continue

            l2_payload = data[EtherHeader.TOTAL_HEADER_LEN:]
            raw_ip_header = l2_payload[:IpHeader.DEFAULT_HEADER_SIZE]
            l3_payload = l2_payload[IpHeader.DEFAULT_HEADER_SIZE:]

            recv_ipheader = IpHeader.parse_header(raw_ip_header)
            print(recv_ipheader)

            repackaged_frame = self.repackage_frame(data)
            try:
                self.raw_sock.sendto(repackaged_frame, (recv_iface, x, y, x, self.my_mac))
            except OSError:
                print('Frame too long: {}'.format(len(repackaged_frame)))

    def start_forward_thread(self):
        self.should_forward = True
        self.forward_thread.start()

    def stop_forward_thread(self):
        self.should_forward = False
        self.forward_thread.join()

