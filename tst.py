import argparse
import os
parser = argparse.ArgumentParser()

parser.add_argument("-i",
                    "--interface",
                    help="network interface to forward to",
                    type=str,
                    default="lo")
parser.add_argument("-p",
                    "--pcap_path",
                    help="path of the pcap file to monitor",
                    type=str,
                    default=os.path.join(os.path.dirname(__file__), "pcap_files", "captured_traffic.pcap"))

a = parser.parse_args()
print(a.interface)
print(a.pcap_path)
