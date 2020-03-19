import socket
import binascii

from mitm_service.mitm_service import MITMService


class NetworkNode:
    def __init__(self, interface, ip, mac, gateway_ip, gateway_mac, hostname, os=None):
        self.interface = interface
        self.ip = ip
        self.mac = mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.hostname = hostname
        self.os = os

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

    def start_mitm(self):
        self.mitm_service.start_mitm()

    def stop_mitm(self):
        self.mitm_service.stop_mitm()

    def add_disruption_rule(self, *args, **kwargs):
        self.mitm_service.add_disruption_rule(*args, **kwargs)

    def restore_layer_traffic(self, layer):
        self.mitm_service.add_disruption_rule(layer, lambda header, payload: (header, payload))
