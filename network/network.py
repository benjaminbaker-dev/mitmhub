from network import network_utils
from . import discovery
from .network_node import NetworkNode


class Network:
    def __init__(self, name):
        self.name = name

        gateway_ip, interface = network_utils.get_default_gateway_ip_and_interface()
        self.gateway_ip = gateway_ip
        self.gateway_mac = network_utils.get_mac(self.gateway_ip)
        self.slash_notation_ip_range = network_utils.generate_slash_notation_net_mask(interface)

        self.nodes = self._generate_nodes()

    def _generate_nodes(self):
        nmap_data = discovery.run_nmap_scan(self.slash_notation_ip_range)
        scanned_ip_data = nmap_data["scan"]

        node_list = []
        for ip in scanned_ip_data:
            scan_data = scanned_ip_data[ip]
            mac = scan_data["addresses"]["mac"]
            hostname = scan_data["hostnames"][0]["name"] if scan_data["hostnames"] else None
            os = scan_data["osmatch"][0]["name"] if scan_data["osmatch"] else None

            node_list.append(NetworkNode(
                ip=ip,
                mac=mac,
                gateway_ip=self.gateway_ip,
                gateway_mac=self.gateway_mac,
                hostname=hostname,
                os=os
            ))
        return node_list

    def refresh_network(self):
        self.nodes = self._generate_nodes()
