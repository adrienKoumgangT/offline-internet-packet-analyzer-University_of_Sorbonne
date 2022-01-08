from utils.utils import *


def analyse_datagram_icmp(datagram):

    octets_type = datagram[0]
    dec_type = convert_base_b_to_ten(number=octets_type, base=16)

    octets_code = datagram[1]
    dec_code = convert_base_b_to_ten(number=octets_code, base=16)
    # type_icmp, code_name
    if dec_type == 0:
        type_icmp = "Echo Reply"
        if dec_code == 0:
            code_name = "Echo Reply"
        else:
            code_name = "unknown"
    elif dec_type in {1, 2}:
        type_icmp = "unassigned"
        code_name = "Reserved"
    elif dec_type == 3:
        type_icmp = "Destination Unreachable"
        if dec_code == 0:
            code_name = "Destination network unreachable"
        elif dec_code == 1:
            code_name = "Destination host unreachable"
        elif dec_code == 2:
            code_name = "Destination protocol unreachable"
        elif dec_code == 3:
            code_name = "Destination port unreachable"
        elif dec_code == 4:
            code_name = "Fragmentation required, and DF flag set"
        elif dec_code == 5:
            code_name = "Source route failed"
        elif dec_code == 6:
            code_name = "Destination network unknown"
        elif dec_code == 7:
            code_name = "Destination host unknown"
        elif dec_code == 8:
            code_name = "Source host isolated"
        elif dec_code == 9:
            code_name = "Network administratively prohibited"
        elif dec_code == 10:
            code_name = "Host administratively prohibited"
        elif dec_code == 11:
            code_name = "Network unreachable for ToS"
        elif dec_code == 12:
            code_name = "Host unreachable for ToS"
        elif dec_code == 13:
            code_name = "Communication administratively prohibited"
        elif dec_code == 14:
            code_name = "Host Precedence Violation"
        elif dec_code == 15:
            code_name = "Host Precedence Violation"
        else:
            code_name = "unknown"
    elif dec_type == 4:
        type_icmp = "Source Quench"
        if dec_code == 0:
            code_name = "deprecated: Source quench (congestion control)"
        else:
            code_name = "unknown"
    elif dec_type == 5:
        type_icmp = "Redirect Message"
        if dec_code == 0:
            code_name = "Redirect Datagram for the Network"
        elif dec_code == 1:
            code_name = "Redirect Datagram for the Host"
        elif dec_code == 2:
            code_name = "Redirect Datagram for the ToS & network"
        elif dec_code == 3:
            code_name = "Redirect Datagram for the ToS & host"
        else:
            code_name = "unknown"
    elif dec_type == 6:
        type_icmp = "unknown"
        code_name = "deprecated: Alternate Host Address"
    elif dec_type == 7:
        type_icmp = "unknown"
        code_name = "unassigned: Reserved"
    elif dec_type == 8:
        type_icmp = "Echo Request"
        if dec_code == 0:
            code_name = "Echo request (used to ping)"
        else:
            code_name = "unknown"
    elif dec_type == 9:
        type_icmp = "Router Advertisement"
        if dec_code == 0:
            code_name = "Router Advertisement"
        else:
            code_name = "unknown"
    elif dec_type == 10:
        type_icmp = "Router Solicitation"
        if dec_code == 0:
            code_name = "Router discovery/selection/solicitation"
        else:
            code_name = "unknown"
    elif dec_type == 11:
        type_icmp = "Time Exceeded"
        if dec_code == 0:
            code_name = "TTL expired in transit"
        elif dec_code == 1:
            code_name = "Fragment reassembly time exceeded"
        else:
            code_name = "unknown"
    elif dec_type == 12:
        type_icmp = "Parameter Problem: Bad IP header"
        if dec_code == 0:
            code_name = "Pointer indicates the error"
        elif dec_code == 1:
            code_name = "Missing a required option"
        elif dec_code == 2:
            code_name = "Bad length"
        else:
            code_name = "unknown"
    elif dec_type == 13:
        type_icmp = "Timestamp"
        if dec_code == 0:
            code_name = "Timestamp"
        else:
            code_name = "unknown"
    elif dec_type == 14:
        type_icmp = "Timestamp Reply"
        if dec_code == 0:
            code_name = "Timestamp Reply"
        else:
            code_name = "unknown"
    elif dec_type == 15:
        type_icmp = "Information Request"
        if dec_code == 0:
            code_name = "deprecated: Information Request"
        else:
            code_name = "unknown"
    elif dec_type == 16:
        type_icmp = "Information Reply"
        if dec_code == 0:
            code_name = "deprecated: Information Reply"
        else:
            code_name = "unknown"
    elif dec_type == 17:
        type_icmp = "Address Mask Request"
        if dec_code == 0:
            code_name = "deprecated: Address Mask Request"
        else:
            code_name = "unknown"
    elif dec_type == 18:
        type_icmp = "Address Mask Reply"
        if dec_code == 0:
            code_name = "deprecated: Address Mask Reply"
        else:
            code_name = "unknown"
    elif dec_type == 19:
        type_icmp = "reserved"
        code_name = "reserved: Reserved for security"
    elif dec_type in {20, 21, 22, 23, 24, 25, 26, 27, 28, 29}:
        type_icmp = "reserved"
        code_name = "reserved: Reserved for robustness experiment"
    elif dec_type == 30:
        type_icmp = "Traceroute"
        if dec_code == 0:
            code_name = "deprecated: information Request"
        else:
            code_name = "unknown"
    elif dec_type == 31:
        type_icmp = "deprecated"
        code_name = "deprecated: Datagram Conversion Error"
    elif dec_type == 32:
        type_icmp = "deprecated"
        code_name = "deprecated: Mobile Host Redirect"
    elif dec_type == 33:
        type_icmp = "deprecated"
        code_name = "deprecated: MWhere-Are_you (originally meant for IPv6)"
    elif dec_type == 34:
        type_icmp = "deprecated"
        code_name = "deprecated: Here-I-Am (originally meant for IPv6)"
    elif dec_type == 35:
        type_icmp = "deprecated"
        code_name = "deprecated: Mobile Registration Request"
    elif dec_type == 36:
        type_icmp = "deprecated"
        code_name = "deprecated: Mobile Registration Reply"
    elif dec_type == 37:
        type_icmp = "deprecated"
        code_name = "deprecated: Domain Name Request"
    elif dec_type == 38:
        type_icmp = "deprecated"
        code_name = "deprecated: Domain Name Reply"
    elif dec_type == 39:
        type_icmp = "deprecated"
        code_name = "deprecated: SKIP Algorithm Discovery Protocol, Simple Key-Management for Internet Protocol"
    elif dec_type == 40:
        type_icmp = "unknown"
        code_name = "Photuris, Security failures"
    elif dec_type == 41:
        type_icmp = "experimental"
        code_name = "experimental: ICMP for experimental mobility protocols such as Seamoby"
    elif dec_type == 42:
        type_icmp = "Extended Echo Request"
        if dec_code == 0:
            code_name = "Request Extended Echo (Xping)"
        else:
            code_name = "unknown"
    elif dec_type == 43:
        type_icmp = "Extended Echo Reply"
        if dec_code == 0:
            code_name = "No Error"
        elif dec_code == 1:
            code_name = "Malformed Query"
        elif dec_code == 2:
            code_name = "No Such Interface"
        elif dec_code == 3:
            code_name = "No Such Table Entry"
        elif dec_code == 4:
            code_name = "Multiple Interfaces Satisfy Query"
        else:
            code_name = "unknown"
    elif dec_type == 253:
        type_icmp = "Experimental"
        code_name = "Experimental: RFC3692-style Experiment 1 (RFC 4727)"
    elif dec_type == 254:
        type_icmp = "Experimental"
        code_name = "Experimental: RFC3692-style Experiment 2 (RFC 4727)"
    elif dec_type == 255:
        type_icmp = "Reserved"
        code_name = "Reserved"
    else:
        type_icmp = "unassigned"
        code_name = "Reserved"

    octets_checksum = datagram[2:4]
    octets_identifier = datagram[4:6]
    octets_sequence_number = datagram[6:8]
    octets_data = datagram[8:]

    return {"ICMP": "TODO"}
