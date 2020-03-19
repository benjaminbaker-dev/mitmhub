class NetworkNode:
    def __init__(self, ip, mac, gateway_ip, gateway_mac, hostname, os=None):
        self.ip = ip
        self.mac = mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.hostname = hostname
        self.os = os

        self.mitm_service = None

    def start_mitm(self):
        pass

    def stop_mitm(self):
        pass

    def add_disruption_rule(self, layer, rule):
        pass

    def restore_layer_traffic(self, layer):
        pass
