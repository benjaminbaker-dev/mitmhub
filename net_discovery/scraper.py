import ipaddress

import netifaces

IP_SECTOR_SEPARATOR = "."


class NotIP4(Exception):
    pass


def _format_ip4_with_net_mask(ip, net_mask):
    """
    resets relevant sectors of ip according to netmask
    :param ip: IP4 address
    :param net_mask: IP4 net mask
    """
    ip_parts = ip.split(IP_SECTOR_SEPARATOR)
    mask_parts = net_mask.split(IP_SECTOR_SEPARATOR)

    for index in range(len(mask_parts)):
        if mask_parts[index] == "255":
            continue

        ip_parts[index] = mask_parts[index]

    return ".".join(ip_parts)


def _get_interface_ip4_data(interface):
    """
    get this machines IP4 address, subnet mask and broadcast address
    :param interface: network interface to get network data from
    """
    if_address_data = netifaces.ifaddresses(interface)
    ip4_address_data = if_address_data[netifaces.AF_INET]

    if not ip4_address_data:
        raise NotIP4("the interface provided has no IP4 data")

    ip4_address_data = ip4_address_data[0]
    return ip4_address_data["addr"], ip4_address_data["netmask"], ip4_address_data["broadcast"]


def generate_ip4_list(interface="en0"):
    """
    returns list of potential ip addresses on network, excluding this machine and broadcast
    :param interface: network interface to get network data from
    """
    ip, net_mask, broadcast = _get_interface_ip4_data(interface)
    formatted_ip = _format_ip4_with_net_mask(ip, net_mask)

    slash_notation_mask = "{}/{}".format(formatted_ip, net_mask)
    ip_list = [str(ip) for ip in ipaddress.IPv4Network(slash_notation_mask)]

    ip_list.remove(ip)
    ip_list.remove(broadcast)
    return ip_list

# TODO: ping to discover os - see pyping
