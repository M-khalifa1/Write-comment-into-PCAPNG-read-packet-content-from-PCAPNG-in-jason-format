from scapy.all import *

def read_from_packet_to_json_format(pcapng_file, packet_number):

    # Read the PCAPNG file
    packets = rdpcap(pcapng_file)

    # enter packet number to extract
    packet_number = packet_number

    # Extract the packet content
    packet = packets[packet_number]
    packet_json = packet.show(dump=True)

    # Print the JSON output to the console
    print(packet_json)

def add_comment_to_packet(pcapng_file, comment_text, packet_number):
    # Read in the PCAPNG file
    packets = rdpcap(pcapng_file)

    # Get the packet at the specified index
    packet = packets[packet_number]
    # Add the comment in the packet's header
    packet.options.append(comment_text)

    # Write the modified packets to a new PCAPNG file
    new_file = pcapng_file.replace(pcapng_file, 'New_dhcp.pcapng')
    wrpcap(new_file, packets)

add_comment_to_packet('dhcp.pcapng','This is a comment',1)

read_from_packet_to_json_format("dhcp.pcapng",3)


