import argparse
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP
import datetime

class ProSniffer:
    def __init__(self, interface=None, filter_str=None, save_file=None):
        self.interface = interface
        self.filter_str = filter_str
        self.save_file = save_file
        self.captured_packets = []

    def packet_callback(self, packet):
        
        if IP in packet:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
    
            proto_name = "OTHER"
            if TCP in packet:
                proto_name = "TCP"
            elif UDP in packet:
                proto_name = "UDP"
            elif ICMP in packet:
                proto_name = "ICMP"

            
            log_msg = f"[{timestamp}] {proto_name:4} | {ip_src} -> {ip_dst}"
            
            if TCP in packet:
                log_msg += f" | Port: {packet[TCP].sport} -> {packet[TCP].dport}"
            elif UDP in packet:
                log_msg += f" | Port: {packet[UDP].sport} -> {packet[UDP].dport}"

            print(log_msg)
            
            
            self.captured_packets.append(packet)

    def start(self):
        """شروع فرآیند شنود"""
        print(f"[*] Initializing Sniffer on {self.interface if self.interface else 'default interface'}...")
        print(f"[*] Filter: {self.filter_str if self.filter_str else 'None'}")
        print("[*] Press Ctrl+C to stop and save.")
        print("-" * 60)

        try:
            
            sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=self.packet_callback,
                store=0
            )
        except KeyboardInterrupt:
            print("\n[!] Stopping sniffer...")
        except Exception as e:
            print(f"\n[!] Error: {e}")
        finally:
            self.save_data()

    def save_data(self):
        
        if self.save_file and self.captured_packets:
            print(f"[*] Saving {len(self.captured_packets)} packets to {self.save_file}...")
            wrpcap(self.save_file, self.captured_packets)
            print("[+] Save successful.")
        elif not self.save_file:
            print("[*] No output file specified. Data not saved.")
        else:
            print("[!] No packets captured to save.")

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Pro Python Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface (e.g., eth0, wlan0, Wi-Fi)")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp', 'udp', 'port 80')")
    parser.add_argument("-o", "--output", help="Output filename (e.g., capture.pcap)")

    args = parser.parse_args()

    sniffer = ProSniffer(
        interface=args.interface,
        filter_str=args.filter,
        save_file=args.output
    )
    sniffer.start()
