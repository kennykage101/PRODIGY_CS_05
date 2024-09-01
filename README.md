# Packet Sniffer

This Python script is a packet sniffer that captures and analyzes network packets using a raw socket. It consists of two main functions: `parse_packet` and `packet_sniffer`.

## `parse_packet` Function

The `parse_packet` function takes a bytes object representing a captured packet as input and returns a tuple containing the following information extracted from the packet:

1. Source IP address (str)
2. Destination IP address (str)
3. Protocol name (str)
4. Time-to-Live (TTL) value (int)
5. Payload data (bytes)

Here's how the function works:

1. It extracts the first 20 bytes of the packet, which represent the IP header.
2. It unpacks the IP header using the `struct.unpack` function, which extracts various fields from the header.
3. It calculates the length of the IP header based on the "Internet Header Length" (IHL) field.
4. It extracts the TTL value, protocol number, source IP address, and destination IP address from the unpacked header fields.
5. It maps the protocol number to a protocol name (e.g., "ICMP", "TCP", "UDP") using a dictionary. If the protocol number is not recognized, it sets the protocol name to "Unknown".
6. It extracts the payload data by slicing the packet from the end of the IP header.
7. It converts the payload data to a hexadecimal string using the `binascii.hexlify` function.

## `packet_sniffer` Function

The `packet_sniffer` function is the main entry point of the script. It creates a raw socket using the `socket` module and binds it to all available network interfaces (`0.0.0.0`). It then enters an infinite loop where it performs the following steps:

1. It receives a packet from the raw socket using the `recvfrom` method.
2. It passes the received packet to the `parse_packet` function to extract relevant information.
3. It prints the extracted information (source IP, destination IP, protocol, TTL, and payload) to the console.

The loop continues until the user interrupts the script by pressing `Ctrl+C`. At that point, the script prints a message indicating that the packet sniffer has stopped.

## Usage

To run the packet sniffer, simply execute the script. Note that running this script may require administrative privileges, depending on your operating system and network configuration.


Once the script is running, it will start capturing and analyzing network packets. The extracted information for each packet will be printed to the console.
