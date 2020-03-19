import socket
import binascii

from network import network_utils
from . import discovery
from .network_node import NetworkNode


class Network:
    def __init__(self, name):
        self.name = name

        self.gateway_ip, self.interface = network_utils.get_default_gateway_ip_and_interface()
        self.gateway_mac = network_utils.get_mac(self.gateway_ip)
        self.slash_notation_ip_range = network_utils.generate_slash_notation_net_mask(self.interface)

        print("starting network map on subnet {}, this could take a while...".format(self.slash_notation_ip_range))
        self.nodes = self._generate_nodes()
        print("successfully mapped network")

    @property
    def gateway_ip_bytes(self):
        return socket.inet_aton(self.gateway_ip)

    @property
    def gateway_mac_bytes(self):
        return binascii.unhexlify(self.gateway_mac.replace(':', ''))

    def _generate_nodes(self):
        up_addresses_on_subnet = discovery.run_subnet_discovery(self.slash_notation_ip_range)

        node_list = []
        for ip, scan_data in up_addresses_on_subnet.items():
            if scan_data['status']['reason'] == 'localhost-response':
                continue
            mac = scan_data["addresses"]["mac"]

            node_list.append(NetworkNode(
                interface=self.interface,
                ip=ip,
                mac=mac,
                gateway_ip=self.gateway_ip,
                gateway_mac=self.gateway_mac
            ))
        return node_list

    def refresh_network(self):
        self.nodes = self._generate_nodes()
