from scapy.all import *
from scapy.layers.l2 import Ether, ARP

import netifaces

ARP_REQUEST = 1
ARP_REPLY = 2
ARP_REQUEST_TIMEOUT = 5  # seconds
IP_PART_SEPARATOR = "."
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def get_mac(target_ip, mac_resolve_max_tries=5):
    """
    queries network for MAC address corresponding to :param target_ip
    :param target_ip: IP address
    :param mac_resolve_max_tries: amount of times to try resolve mac address
    :return: mac address that matches :param target_ip
    """
    arp_response = None
    try_count = 0

    while not arp_response:
        if try_count > mac_resolve_max_tries:
            raise ValueError("cannot resolve {}. are you sure it exists ?".format(target_ip))

        arp_request = Ether(dst=BROADCAST_MAC) / ARP(op=ARP_REQUEST, pdst=target_ip)
        arp_response = srp(arp_request, timeout=ARP_REQUEST_TIMEOUT, verbose=False)[0]
        try_count += 1

    target_mac = arp_response[0][0][1].hwsrc
    return target_mac


def get_default_gateway_ip():
    data = netifaces.gateways()
    return list(data['default'].values())[0][0]


def _format_ip4_with_net_mask(ip, net_mask):
    """
    resets relevant sectors of ip according to netmask
    :param ip: IP4 address
    :param net_mask: IP4 net mask
    """
    ip_parts = ip.split(IP_PART_SEPARATOR)
    mask_parts = net_mask.split(IP_PART_SEPARATOR)

    for index in range(len(mask_parts)):
        if mask_parts[index] == "255":
            continue

        ip_parts[index] = mask_parts[index]

    return ".".join(ip_parts)


def _get_active_bits(net_mask):
    mask_parts = net_mask.split(IP_PART_SEPARATOR)
    active_bits = 0

    for part in mask_parts:
        active_bits += bin(int(part)).count("1")

    return active_bits


def _get_interface_ip4_data(interface):
    """
    get this machines IP4 address, subnet mask and broadcast address
    :param interface: network interface to get network data from
    """
    if_address_data = netifaces.ifaddresses(interface)
    ip4_address_data = if_address_data[netifaces.AF_INET]

    if not ip4_address_data:
        raise ValueError("the interface provided has no IP4 data")

    ip4_address_data = ip4_address_data[0]
    return ip4_address_data["addr"], ip4_address_data["netmask"], ip4_address_data["broadcast"]


def generate_slash_notation_net_mask(interface="en0"):
    """
    returns list of potential ip addresses on network, excluding this machine and broadcast
    :param interface: network interface to get network data from
    """
    ip, net_mask, broadcast = _get_interface_ip4_data(interface)
    formatted_ip = _format_ip4_with_net_mask(ip, net_mask)
    active_bits = _get_active_bits(net_mask)

    slash_notation_mask = "{}/{}".format(formatted_ip, active_bits)
    return slash_notation_mask
