from scapy.all import *

def packet_callback(packet):

    print("\n------------------------")

    if packet.haslayer(IP):

        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)

        proto = packet[IP].proto

        if proto == 6:
            print("Protocol: TCP")
        elif proto == 17:
            print("Protocol: UDP")
        elif proto == 1:
            print("Protocol: ICMP")
        else:
            print("Protocol:", proto)

        if packet.haslayer(Raw):
            print("Payload:")
            print(packet[Raw].load)

print("Network Sniffer Started...")
print("Press CTRL + C to Stop")

sniff(prn=packet_callback, store=False)