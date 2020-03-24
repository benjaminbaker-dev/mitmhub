import socket
import binascii
import json

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

            mac = scan_data["addresses"].get("mac")
            if mac:
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

    def get_node_by_mac(self, mac_addr):
        """
        Given a unique mac, get the network node with that mac
        :param mac_addr: mac to search
        :return: node on this network with the given mac, or None if none match
        """
        for node in self.nodes:
            if node.mac == mac_addr:
                return node
        return None

    def run_detailed_scan_on_node(self, mac_addr):
        """
        Given a unique mac, run detailed scan on corresponding node
        :param mac_addr: mac to search
        """
        node = self.get_node_by_mac(mac_addr)
        if node:
            node.fill_detailed_tags()

    def start_mitm_by_mac(self, node_mac):
        """
        Start a mitm on the node with the given MAC
        :param node_mac: the mac to start on
        :return: None
        """
        node = self.get_node_by_mac(node_mac)
        node.start_mitm()

    def stop_mitm_by_mac(self, node_mac):
        """
        Stop a mitm on the node with the given MAC
        :param node_mac: the mac to stop the mitm on
        :return: None
        """
        node = self.get_node_by_mac(node_mac)
        node.stop_mitm()

    def get_node_data_by_mac(self, node_mac):
        """
        Get the json representation of a node based on its MAC
        :param node_mac: the mac whose data to fetch
        :return: The json of the node data as STRING
        """
        node = self.get_node_by_mac(node_mac)
        return json.dumps(node.to_json())

    def json_node_query_supported_rules(self, query_json):
        """
        Query the supported rules of a specific node
        :param query_json: a json of the form:
            {
            "node_id":<mac_of_node>
            }
        :return: the response to the query as a STRING
        """
        node_mac = query_json['node_id']
        node = self.get_node_by_mac(node_mac)
        if node is None:
            supported_functions = {}
        else:
            supported_functions = node.json_query_supported_filters()
        response_json = {
            'node_id': node_mac,
            'response': supported_functions
        }
        return json.dumps(response_json)

    def json_node_request_add_rule(self, query_json):
        """
        Request a specific node to add a rule
        :param query_json: a json of the form:
            {
            "node_id":<mac_of_node>,
            "request":{
                "filter_name":{
                    "filter_arg_1":"value_1",
                    "filter_arg_2":"value_2",
                    ...
                },
                ...
                }
            }
        :return: response json as a STRING
        """
        node_mac = query_json['node_id']
        node = self.get_node_by_mac(node_mac)
        add_rule_result = node.json_add_rule(query_json['request'])
        response_json = {
            'node_id': node_mac,
            'response': add_rule_result
        }
        return json.dumps(response_json)

    def to_json(self):
        """
        dump a json representation of the network
        :return:
        """
        nodes_json = []
        for node in self.nodes:
            nodes_json.append(node.to_json())
        json_repr = {
            'network_name': self.name,
            'network_gateway': self.gateway_ip,
            'network_interface': self.interface,
            'network_nodes': nodes_json
        }
        return json_repr

    def get_json_str(self):
        return json.dumps(self.to_json())
