[![license](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)

# PcapRelay

PcapRelay is a Python project that listens to a pcap file and sends any received packet to a network interface. It's a handy tool for relaying captured network traffic from a pcap file to a live network interface for further analysis or testing.

## Prerequisites

Before using PcapRelay, you need to have the following dependencies installed:

- Python 3.x
- Scapy (a Python library for packet manipulation)
- Watchdog (a Python library for monitoring file system events)
- Tcpdump (used for capturing network packets)

You can install these dependencies using the `requirements.txt` file included with this project:

```bash
pip install -r requirements.txt
```

## Project Structure

The project directory is organized as follows:

```
PcapRelay/
├───pcap_relay.py
│    -The main Python script responsible for relaying
│      captured network packets from pcap files to a specified network interface.
│
├───log/
│   └── pacap_relay.log
│       - Log files containing runtime information and events.
│
├───pcap_files/
│   ├── captured_traffic.pcap
│       - Main pcap file containing captured network traffic.
│
└───scripts/
    └── main.sh
        - Shell script for capturing network packets and updating pcap files.

```

- `pcap_relay.py`: The Python script responsible for listening to the pcap file and relaying packets to a network interface.
- `log/`: The directory where log files are stored.
- `pcap_files/`: The directory containing pcap files.
- `scripts/`: The directory containing the `main.sh` script used for capturing network packets.

## Usage

To relay captured packets from a PCAP (Packet Capture) file to a network interface, you can use the `pcap_relay.py` script. Follow the steps below:

1. Make sure you have the necessary dependencies installed as mentioned in the "Prerequisites" section.

2. Open your terminal.

3. Run the following command, replacing `<path_to_pcap_file>` with the actual path to your PCAP file and `<interface_name>` with the name of your network interface:

```bash
python pcap_relay.py -f <path_to_pcap_file> -i <interface_name>
```

## Stand alone test (optional)

You can generate the pcap file by yourself using tcpdump in order to test the PcapRelay.
To do so:

1. Open a terminal and run the `pcap_relay.py`python script without arguments so that it will take the default ones
   - `wlan0` is the default interface to monitor
   - `pcap_files/capture_traffic.pcap` is the monitored pcap file`

The `pcap_relay.py` script will continuously monitor the `pcap_files/` directory for changes in the pcap files and relay new packets to the specified network interface ("lo" by default).

```bash
python pcap_relay.py
```

2. Open a second terminal and run the `main.sh` script that will capture PING network packets frow `wlan0` interface and create or update these pcap files:
   - `captured_traffic.pcap` represents the packets captured on the `wlan0` network interface.
   - `lo_captured_traffic.pcap` represent the packets forwared by the PcapRelay to the loopback interface.

You can compare later the content for the two pcap files and they should be identical.

```bash
cd scripts
./main.sh
```
