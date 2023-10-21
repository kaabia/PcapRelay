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
                logger.debug(f"Sending pkt: <{pkt}> to <{interface}>")
            except Exception as err:
                logger.error(f"ERROR occurred while processing packed <{pkt}>: {err}")
                sys.exit(0)

    def on_modified(self, event):
        """
        Callback triggered whenever a file system event is occurred
        """
        if event.is_directory or not event.src_path.endswith(pcap_file) or event.event_type != "modified":
            return None
        try:
            new_packets = rdpcap(event.src_path)
            if(len(new_packets)) > 0:
                self.new_packets_number = len(new_packets)
                logger.info(f"{len(new_packets)} packet found in {pcap_file}")
                if self.new_packets_number > self.old_packets_number:
                    logger.info(f"New {self.new_packets_number - self.old_packets_number} packets are added")
                    self.process_packet(new_packets[self.old_packets_number:])
                    self.old_packets_number = self.new_packets_number
                    logger.info(f"Total pkt counter = {self.old_packets_number}")
        except Exception as err:
            # rdpcap fails when no data could be read! at first event received.
            # it reflects that the file is created.
            logger.error(err)

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
