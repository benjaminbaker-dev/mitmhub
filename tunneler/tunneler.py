from socket import *
from network_headers import EtherHeader, IpHeader
import struct

def recv_ip_loop():
    print('intializing...')
    ins = socket(AF_PACKET, SOCK_RAW, 0x0800)  # 3 = ETH_P_ALL
    ins.setsockopt(SOL_SOCKET, SO_RCVBUF, 212992)
    ins.bind(('eno1', 0x0800))

    #raw_sock.bind(('eno1', IPPROTO_RAW))
    #raw_sock.setsockopt(IPPROTO_RAW, IP_HDRINCL, 1)
    while True:
        data, addr = ins.recvfrom(212992)
        raw_ether_header = data[:EtherHeader.TOTAL_HEADER_LEN]
        l2_payload = data[EtherHeader.TOTAL_HEADER_LEN:]
        raw_ip_header = l2_payload[:IpHeader.DEFAULT_HEADER_SIZE]
        l3_payload = l2_payload[IpHeader.DEFAULT_HEADER_SIZE:]

        recv_etherheader = EtherHeader.parse_header(raw_ether_header)
        recv_ipheader = IpHeader.parse_header(raw_ip_header)
        print(recv_ipheader)

def main():
    recv_ip_loop()

if __name__ == '__main__':
    main()