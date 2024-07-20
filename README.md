# pip install scapy
# Packet Sniffer Tool

This repository contains a simple Python-based packet sniffer tool that captures and analyzes network packets. The tool displays relevant information such as source and destination IP addresses, protocols, and payload data. It is intended for educational purposes and should be used ethically.

## Features

- Capture network packets in real-time.
- Display source and destination IP addresses.
- Identify and display the protocol (TCP, UDP, ICMP).
- Show source and destination ports for TCP and UDP.
- Display payload data of captured packets.

## Prerequisites

- Python 3.x
- Scapy library

## Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/your-username/packet-sniffer-tool.git
    cd packet-sniffer-tool
    ```

2. **Install Scapy:**

    ```sh
    pip install scapy
    ```

## Usage

1. **Run the program:**

    ```sh
    sudo python packet_sniffer.py
    ```

    Note: Running this script might require administrative privileges.

2. **Monitor the output:**

    The script will capture and display information about the network packets, including:
    - Source and Destination IP addresses
    - Protocol (TCP, UDP, ICMP)
    - Source and Destination Ports (for TCP/UDP)
    - Payload data

## Ethical Use

- **Education and Research:** This tool is intended for educational purposes and network traffic analysis in a controlled environment.
- **Authorized Testing:** Use this tool only on networks you own or have permission to analyze. Unauthorized packet sniffing is illegal and unethical.
- **Data Privacy:** Be aware of privacy laws and regulations. Avoid capturing or inspecting sensitive or personal data without explicit consent.

## Example Output

