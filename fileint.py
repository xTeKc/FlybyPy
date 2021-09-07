import netfilterqueue
import scapy.all as scapy

def process_packet():
    scapy_packet = scapy.IP(packet.get_payload())