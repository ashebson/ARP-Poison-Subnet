import ipaddress
import textwrap
from os import popen
from parse import *
import mdns_querying

def calculate_subnet_address(mask, example):
    mask = textwrap.wrap(mask,2)[1:]
    example = example.split('.')
    address = ''
    for i in range(4):
        address += str(int(mask[i],base=16) & int(example[i])) + '.'
    return address[:-1]

def cidr(mask):
    return str(bin(int(mask,base=16)).count('1'))

def get_subnet_ips():
    ifconfig = search('en0:{}status', popen('ifconfig').read())[0]
    my_ip = search('inet {} ', ifconfig)[0]
    subnet_mask = search('netmask {} ', ifconfig)[0]
    subnet_address = calculate_subnet_address(subnet_mask, my_ip)
    ips = ipaddress.IPv4Network(subnet_address + '/' + cidr(subnet_mask))
    return ips

def get_default_gateway():
    return search('gateway: {}\n',popen('route get default | grep gateway').read())[0]

def get_subnet_hostnames(verbose=True):
    ips = get_subnet_ips()
    table = []
    for target in ips:
        target = str(target)
        try:
            hostname = mdns_querying.get_hostname(target)
            if verbose:
                print(target, hostname)
            table.append((target, hostname))
        except Exception as err:
            if verbose:
                print(err)

