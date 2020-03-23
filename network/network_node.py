import socket
import binascii

from network.discovery import run_detailed_scan
from mitm_service.mitm_service import MITMService
import json

class NetworkNode:
    def __init__(self, interface, ip, mac, gateway_ip, gateway_mac, tags=None):
        self.interface = interface
        self.ip = ip
        self.mac = mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac

        self.tags = tags or {}

        self.mitm_service = MITMService(
            self.interface,
            self.ip,
            self.gateway_ip,
            self.mac,
            self.gateway_mac
        )

    @property
    def ip_bytes(self):
        return socket.inet_aton(self.ip)

    @property
    def mac_bytes(self):
        return binascii.unhexlify(self.mac.replace(':', ''))

    def fill_detailed_tags(self):
        detailed_tags = run_detailed_scan(self.ip)
        for key, value in detailed_tags.items():
            self.tags[key] = value

    def start_mitm(self):
        self.mitm_service.start_mitm()

    def stop_mitm(self):
        self.mitm_service.stop_mitm()

    def add_filter(self, *args, **kwargs):
        self.mitm_service.add_filter(*args, **kwargs)

    def restore_traffic(self):
        self.mitm_service.l2_tunnel._packet_filters = []

    def to_json(self):
        json_repr = {
            'interface':self.interface,
            'ip':self.ip,
            'mac':self.mac,
            'gateway_ip':self.gateway_ip,
            'gateway_mac':self.gateway_mac,
            'tags': self.tags,
            'is_mitm_running':self.mitm_service.is_mitm_running
        }
        return json_repr

    def get_json_str(self):
        return json.dumps(self.to_json())

    def __repr__(self):
        repr_str = "NetworkNode(ip={}, mac={}, tags={})".format(self.ip, self.mac, self.tags)
        return repr_str

    def __str__(self):
        return self.__repr__()
