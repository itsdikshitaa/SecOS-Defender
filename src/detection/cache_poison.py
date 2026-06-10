from scapy.all import sniff, ARP

class CachePoisonDetector:
    def __init__(self):
        self.arp_table = {}
        
    def detect_arp_spoofing(self, packet):
        if ARP in packet and packet[ARP].op == 2:  # ARP response
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            if self.arp_table.get(ip) and self.arp_table[ip] != mac:
                print(f"[ALERT] ARP Cache Poisoning: {ip} changed from {self.arp_table[ip]} to {mac}")
            self.arp_table[ip] = mac

if __name__ == "__main__":
    detector = CachePoisonDetector()
    sniff(prn=detector.detect_arp_spoofing, filter="arp", store=0)
