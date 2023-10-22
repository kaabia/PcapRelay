# Remove any existing captured_traffic.pcap file in the parent directory.
rm -rf ../pcap_files/captured_traffic.pcap

# Use tcpdump to capture ICMP traffic on the 'wlan0' interface and write it to captured_traffic.pcap.
tcpdump 'icmp' -i wlan0 -w ../pcap_files/captured_traffic.pcap -U &

# Use tcpdump to capture ICMP traffic on the loopback (lo) interface and write it to lo_captured_traffic.pcap.
tcpdump 'icmp' -i lo -w ../pcap_files/lo_captured_traffic.pcap -U &

# Send 10 ICMP ping requests to 8.8.8.8 via the 'wlan0' interface and print timestamps for each line using gawk.
ping 8.8.8.8 -I wlan0 -c 10 | gawk '{print strftime("%c: ") $0}'