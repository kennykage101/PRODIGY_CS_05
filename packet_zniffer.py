import socket
import struct
import binascii
from typing import Tuple

def parse_packet(packet: bytes) -> Tuple[str, str, str, int, bytes]:
    """
    Parse the captured packet and extract relevant information.

    Args:
        packet (bytes): The captured packet data.

    Returns:
        Tuple[str, str, str, int, bytes]: A tuple containing the source IP address,
            destination IP address, protocol name, TTL value, and payload data.
    """
    ip_header = packet[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    protocol_name = protocol_map.get(protocol, "Unknown")

    payload = packet[iph_length:]
    payload_hex = binascii.hexlify(payload)



def packet_sniffer():
    """
    Capture and analyze network packets using a raw socket.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
        sock.bind(("0.0.0.0", 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        print("Packet sniffer started. Press 'Ctrl+C' to stop.")

        try:
            while True:
                packet = sock.recvfrom(65565)[0]
                s_addr, d_addr, protocol_name, ttl, payload_hex = parse_packet(packet)

                print(f"Source IP: {s_addr}")
                print(f"Destination IP: {d_addr}")
                print(f"Protocol: {protocol_name}")
                print(f"TTL: {ttl}")
                print(f"Payload: {payload_hex.decode()}")
                print()

        except KeyboardInterrupt:
            print("Packet sniffer stopped.")

if __name__ == "__main__":
    packet_sniffer()
