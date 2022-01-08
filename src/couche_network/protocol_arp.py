from utils.utils import *


def analyse_packet_arp(packet: list):
    dict_hardware_type = {1: "Ethernet", 2: "Experimental Ethernet", 3: "Amateur Radio AX.25",
                          4: "Proteon ProNET Token Ring", 5: "Chaos", 6: "IEEE 802 Networks",
                          7: "ARCNET", 8: "Hyperchannel", 9: "Lanstar", 10: "Autonet Short Address",
                          11: "LocalTalk", 12: "LocalNet", 13: "Ultra link", 14: "SMDS",
                          15: "Frame Relay", 16: "Asynchronous Transmission Mode (ATM)",
                          17: "HDLC", 18: "Fibre Channel", 19: "Asynchronous Transmission Mode (ATM)",
                          20: "Serial Line", 21: "Asynchronous Transmission Mode (ATM)",
                          22: "MIL-STD-188-220", 23: "Metricom", 24: "IEEE 1394.1995", 25: "MAPOS",
                          26: "Twinaxial", 27: "EUI-64", 28: "HIPARP", 29: "IP AND ARP over ISO 7816-3",
                          30: "ARPSec", 31: "IPsec tunnel", 32: "TIA-102 Project 25 Common Air Interface (CAI)"}

    dict_protocol_type = {"0800": "IP"}
    dict_opcode = {1: "Request", 2: "Reply"}

    octets_hardware_type = "".join(packet[0:2])
    dec_hardware_type = convert_base_b_to_ten(number=octets_hardware_type, base=16)
    if dec_hardware_type in dict_hardware_type.keys():
        hardware_type = dict_hardware_type[dec_hardware_type]
    else:
        hardware_type = "UNKNOWN"

    octets_protocol_type = "".join(packet[2:4])
    if octets_protocol_type in dict_protocol_type.keys():
        protocol_type = dict_protocol_type[octets_protocol_type]
    else:
        protocol_type = "UNKNOWN"

    octets_hardware_address_size = packet[4]
    dec_hardware_size = convert_base_b_to_ten(number=octets_hardware_address_size, base=16)
    octets_protocol_address_size = packet[5]
    dec_protocol_size = convert_base_b_to_ten(number=octets_protocol_address_size, base=16)

    octets_opcode = "".join(packet[6:8])
    dec_opcode = convert_base_b_to_ten(number=octets_opcode, base=16)
    if dec_opcode in dict_opcode.keys():
        opcode = dict_opcode[dec_opcode]
    else:
        opcode = "UNKNOWN"

    index_begin = 8
    list_octets_source_mac_address = packet[index_begin: index_begin+dec_hardware_size]
    octets_source_mac_address = "".join(list_octets_source_mac_address)
    source_mac_address = ":".join(list_octets_source_mac_address)

    index_begin += dec_hardware_size
    list_octets_source_ip_address = packet[index_begin: index_begin+dec_protocol_size]
    octets_source_ip_address = "".join(list_octets_source_ip_address)
    source_ip_address = get_address_ip(a_d=list_octets_source_ip_address)

    index_begin += dec_protocol_size
    list_octets_destination_mac_address = packet[index_begin: index_begin+dec_hardware_size]
    octets_destination_mac_source = "".join(list_octets_destination_mac_address)
    destination_mac_address = ":".join(list_octets_destination_mac_address)

    index_begin += dec_hardware_size
    list_octets_destination_ip_address = packet[index_begin: index_begin+dec_protocol_size]
    octets_destination_ip_address = "".join(list_octets_destination_ip_address)
    destination_ip_address = get_address_ip(a_d=list_octets_destination_ip_address)
    index_begin += dec_protocol_size

    final_result = {"ARP HARDWARE TYPE": [octets_hardware_type, dec_hardware_type, hardware_type],
                    "ARP PROTOCOL TYPE": [octets_protocol_type, protocol_type],
                    "ARP HARDWARE SIZE": [octets_hardware_address_size, dec_hardware_size],
                    "ARP PROTOCOL SIZE": [octets_protocol_address_size, dec_protocol_size],
                    "ARP OPCODE": [octets_opcode, dec_opcode, opcode],
                    "ARP SOURCE MAC ADDRESS": [octets_source_mac_address, source_mac_address],
                    "ARP SOURCE IP ADDRESS": [octets_source_ip_address, source_ip_address],
                    "ARP DESTINATION MAC ADDRESS": [octets_destination_mac_source, destination_mac_address],
                    "ARP DESTINATION IP ADDRESS": [octets_destination_ip_address, destination_ip_address]}

    if index_begin+1 < len(packet):
        final_result["ETHERNET TRAILER"] = ["".join(packet[index_begin:])]

    return final_result


def analyse_packet_rarp(packet: list):
    return {"RARP": "TODO"}
