import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP,IP
from scapy.layers.l2 import Ether


TO = 0.5

mdns_request_format = Ether(dst='01:00:5E:00:00:FB') \
                      / IP(dst='224.0.0.251',ttl=255) \
                      / UDP(dport=5353,sport=8080) \
                      / DNS(qdcount=1,ad=1) \
                      / DNSQR(qtype='PTR')


def get_hostname(target):
    formatted_target = '.'.join(target.split('.')[::-1]) + '.in-addr.arpa'
    mdns_request = copy.deepcopy(mdns_request_format)
    mdns_request[DNS].qname = formatted_target
    sendp(mdns_request, verbose=False)

    def mdns_response_filter(raw_packet):
        if DNSQR in raw_packet and DNSRR in raw_packet:
            return mdns_request[DNSQR].qname == raw_packet[DNSQR].qname[:-1]

    mdns_response = sniff(1, lfilter=mdns_response_filter, timeout=TO)
    if len(mdns_response) != 0:
        return mdns_response[0][DNSRR].rdata.decode()
    else:
        raise Exception('unable to reach {}'.format(target))





