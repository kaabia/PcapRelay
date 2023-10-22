'''
_______________________________________________________________________________#

 File    : pcap_relay.py
 Author  : Badr Bacem KAABIA
 Version : 0.1
 Date    : 22 October 2023
 Brief   : monitor pcap packets main file
_______________________________________________________________________________

MIT License

Copyright (c) 2023 Badr Bacem KAABIA

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

_______________________________________________________________________________#
'''
from __future__ import absolute_import
import os
import sys
import logging

from scapy.all import sendp, rdpcap
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logging.basicConfig(level=logging.DEBUG,
                    filename=os.path.join(os.path.dirname(__file__), "log/pacap_relay.log"),
                    filemode="w",
                    format='[%(levelname)s] %(asctime)s - %(name)s : %(message)s')

logger = logging.getLogger("PCAP RELAY")

# Define the interface for sending packets to the loop back
interface = "lo"
pcap_file = "captured_traffic.pcap"

class PcapFileHandler(FileSystemEventHandler):
    """
    Create a custom event handler for monitoring file changes
    """
    rx_frame_counter = 0
    new_packets_number = 0
    old_packets_number = 0

    @staticmethod
    def process_packet(r_packet):
        """
        Process and modify the packet if needed
        """
        for pkt in r_packet:
            try:
                sendp(pkt, iface=interface)
                logger.debug("Sending pkt: <%s> to <%s>", pkt, interface)
            except RuntimeError as err:
                logger.error("Error occurred while sending packed <%s> to interface %s", pkt, err)
                sys.exit(0)

    def on_modified(self, event):
        """
        Callback triggered whenever a file system event is occurred
        """
        if event.is_directory or \
            not event.src_path.endswith(pcap_file) or \
            event.event_type != "modified":
            return

        try:
            new_packets = rdpcap(event.src_path)
            if(len(new_packets)) > 0:
                self.new_packets_number = len(new_packets)
                logger.info("%d packet found in %s", len(new_packets), pcap_file)
                if self.new_packets_number > self.old_packets_number:
                    logger.info("New %d packets are added", self.new_packets_number - self.old_packets_number)
                    self.process_packet(new_packets[self.old_packets_number:])
                    self.old_packets_number = self.new_packets_number
                    logger.info("Total pkt counter : <%d>", self.old_packets_number)
        except FileNotFoundError as file_not_found:
            logger.error("File not found: %s", file_not_found)

if __name__ == "__main__":
    # Create a watchdog observer to monitor the directory containing the pcap file
    logger.info(">> PCAP Relay start.. <<")
    observer = Observer()
    pcap_file_path = os.path.join(os.path.dirname(__file__), "pcap_files")
    observer.schedule(PcapFileHandler(), path=pcap_file_path, recursive=False)
    observer.start()

    try:
        while True:
            # Keep the script running to monitor file changes
            pass
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
