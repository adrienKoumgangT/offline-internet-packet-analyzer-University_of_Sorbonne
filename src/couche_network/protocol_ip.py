# from utils.utils import *
from src.couche_transport.protocol_icmp import *
from src.couche_transport.protocol_tcp import *
from src.couche_transport.protocol_udp import *


def get_flags_and_fragment_offset(flags_frag: list) -> list:
    ff = "".join(flags_frag[0:2])
    b_ff = convert_base_b1_to_b2(number=ff, base1=16, base2=2)
    if len(b_ff) < 16:
        b_ff = ("0" * (16 - len(b_ff))) + b_ff
    return [b_ff[0], b_ff[1], b_ff[2], convert_base_b_to_ten(number="".join(b_ff[3:]), base=2)]


def analyse_datagram_ipv4(packet: list) -> dict:
    """
    Fonction qui me permet d'analyser un packet IPv4

    :param packet: packet à analyser
    :return: return un dictionnaire contenant les informations du packet
    """

    # print(f"packet ipv4 = {packet}")
    # version: indique le numéro de version du protocole IP utilisé (généralement 4)
    octets_version = packet[0][0]
    # Header (longueur d' entete): indique la longueur en nombre de mots de 32 bits (4 octets)
    octets_header_length = packet[0][1]
    header_length = convert_base_b_to_ten(number=octets_header_length, base=16) * 4
    length_options = header_length - 20

    # TOF (Type de service): |D|T|R|C|Service| il est sur 8 bits
    octets_type_of_service = packet[1]
    bit_type_of_service = convert_base_b1_to_b2(number=octets_type_of_service, base1=16, base2=2)
    bit_type_of_service = ("0" * (8 - len(bit_type_of_service))) + bit_type_of_service
    # 4 bits "priorité":
    # D: délai court
    bit_priority_d = bit_type_of_service[3]
    if bit_priority_d == "0":
        priority_d = "Normal"
    else:
        priority_d = "Low"
    # T: haut débit
    bit_priority_t = bit_type_of_service[4]
    if bit_priority_t == "0":
        priority_t = "Normal"
    else:
        priority_t = "High"
    # R: fiabilité élevée
    bit_priority_r = bit_type_of_service[5]
    if bit_priority_r == "0":
        priority_r = "Normal"
    else:
        priority_r = "High"
    # C: Cout faible
    bit_priority_c = bit_type_of_service[6]
    if bit_priority_c == "0":
        priority_c = "Normal"
    else:
        priority_c = "Low"
    # 4 bits "service"
    bit_precedence = bit_type_of_service[:3]
    if bit_precedence == "000":
        precedence = "Routine"
    elif bit_precedence == "001":
        precedence = "Priority"
    elif bit_precedence == "010":
        precedence = "Immediate"
    elif bit_precedence == "011":
        precedence = "Flash"
    elif bit_precedence == "100":
        precedence = "Flash Override"
    elif bit_precedence == "101":
        precedence = "Critical"
    elif bit_precedence == "110":
        precedence = "Internetwork Control"
    elif bit_precedence == "111":
        precedence = "Network Control"
    else:
        precedence = "UNKNOWN"

    bit_dtrc = bit_type_of_service[3:7]
    if bit_dtrc == "0000":
        dtrc = "Normal Service"
    elif bit_dtrc == "0001":
        dtrc = "Minimum monetary Cost"
    elif bit_dtrc == "0011":
        dtrc = "Maximum Reliability"
    elif bit_dtrc == "0100":
        dtrc = "Maximum Throughput"
    elif bit_dtrc == "1000":
        dtrc = "Minimum Delay"
    else:
        dtrc = " "

    # total_length = bloc_ip[2:4]
    # total_length = convert_base(".".join([bloc_ip[2][0], bloc_ip[2][1],
    # bloc_ip[3][0], bloc_ip[3][1]]), 16)
    octets_total_length = "".join([packet[2], packet[3]])
    total_length = convert_base_b_to_ten(number=octets_total_length, base=16)

    octets_identifier = "".join(packet[4:6])
    identifier = convert_base_b_to_ten(number=octets_identifier, base=16)

    # Les flags et le fragment offset
    flags_fragment_offset = get_flags_and_fragment_offset(packet[6:8])
    r = int(flags_fragment_offset[0])
    # DF (Dont't Fragment): vaut 1 si la trame n'est pas fragmentée
    df = int(flags_fragment_offset[1])
    # MF (More Fragment): vaut 1 si la trame a été fragmentée, et si ce fragment n'est pas le dernier
    mf = int(flags_fragment_offset[2])
    fragment_offset = flags_fragment_offset[3]

    octets_ttl = packet[8]
    ttl = convert_base_b_to_ten(number=octets_ttl, base=16)

    octets_protocole = packet[9]
    dec_protocole = convert_base_b_to_ten(number=octets_protocole, base=16)
    if dec_protocole == 1:
        # 1 - ICMP : Internet Control Message Protocol (RFC792)
        protocole = [1, "ICMP"]
    if dec_protocole == 2:
        # 2 - IGMP : Internet Group Management Protocol (RFC1112)
        protocole = [2, "IGMP"]
    elif dec_protocole == 6:
        # 6 - TCP : Transmission Control Protocol (RFC793)
        protocole = [6, "TCP"]
    elif dec_protocole == 8:
        # 8 - EGP : Exterior Gateway Protocol
        protocole = [8, "EGP"]
    elif dec_protocole == 9:
        # 9 - IGP : any private Interior Gateway Protocol
        protocole = [9, "IGP"]
    elif dec_protocole == 17:
        # 17 - UDP : User Datagram Protocol
        protocole = [17, "UDP"]
    elif dec_protocole == 36:
        # 36 - XTP : XTP
        protocole = [36, "XTP"]
    elif dec_protocole == 46:
        # 46 - RSVP : Reservation Protocol
        protocole = [46, "RSVP"]
    else:
        protocole = [dec_protocole, "UNKNOWN"]

    # header_checksum = bloc_ip[10:12]
    header_checksum = "".join([packet[10], packet[11]])

    ip_s = packet[12:16]
    octets_ip_s = "".join(ip_s)
    address_ip_source = get_address_ip(ip_s)
    ip_d = packet[16:20]
    octets_ip_d = "".join(ip_d)
    address_ip_destination = get_address_ip(ip_d)

    if length_options > 0:
        # Le champ Options est codé entre 0 et 40 octets.
        # Il n'est pas obligatoire, mais permet le <<Tunning de l'entete IP>>.
        # Les options sont codées sur le principe TLV (Type, Longueur, Valeur).
        octets_options = packet[20:header_length]
        # Afin de bien gérer les Options, cela doit commencer par un octets de renseignement.
        octet_info_options = octets_options[0]
        bit_info_options = convert_base_b1_to_b2(number=octet_info_options, base1=16, base2=2)
        if len(bit_info_options) < 8:
            bit_info_options = ("0" * (8 - len(bit_info_options))) + bit_info_options
        # Le champ Copie est codé sur 1 bit et indique comment les options doivent etre traitées
        # lors de la fragmentation. Cela signifie que lorsqu'il est positionné à 1,
        # il faut recopier les options dans chaque paquet fragmenté.
        bit_copie_options = bit_info_options[0]
        # Le champ Classe est codé sur 2 bits et indique les différentes catégories d'options existantes.
        bit_class_options = bit_info_options[1:3]
        dec_class_options = convert_base_b_to_ten(number=bit_class_options, base=2)
        if dec_class_options == 0:
            class_options = "Supervision de réseau"
        elif dec_class_options == 1:
            class_options = "Not used"
        elif dec_class_options == 2:
            class_options = "Debug et mesures"
        elif dec_class_options == 3:
            class_options = "Not used"
        else:
            class_options = "Error"
        # Le champ Num*ro est codé sur 5 bits et indique les différentes options existantes.
        bit_numero_options = bit_info_options[3:]
        dec_numero_options = convert_base_b_to_ten(number=bit_numero_options, base=2)
        # TODO: à completer
        if dec_class_options == 0:
            if dec_numero_options == 0:
                # Fin de liste d'option.
                # Utilisé si les options ne se terminent pas à la fin de l'entete (bourrage).
                pass
            elif dec_numero_options == 1:
                # Pas d'opération.
                # Utilisé pour aligner les octets dans une liste d'options.
                pass
            elif dec_numero_options == 2:
                # Restriction de sécurité et de gestion.
                # Destiné aux applications militaires.
                pass
            elif dec_numero_options == 3:
                # Routage lache défini par la source.
                pass
            elif dec_numero_options == 7:
                # Enregistrement de route.
                pass
            elif dec_numero_options == 8:
                # Identificateur de connexion.
                pass
            elif dec_numero_options == 9:
                # Routage strict défini par la source
                pass
            else:
                pass
        elif dec_class_options == 2:
            if dec_numero_options == 4:
                # Horodatage dans l'Internet
                pass
            else:
                pass
        else:
            pass
    else:
        octets_options = None

    if dec_protocole == 1:
        protocole = "ICMP"
        higher_level = analyse_datagram_icmp(datagram=packet[header_length:])
    elif dec_protocole == 6:
        protocole = "TCP"
        higher_level = analyse_segment_tcp(segment=packet[header_length:])
    elif dec_protocole == 17:
        protocole = "UDP"
        # TODO: rédéfinir la fonction analyse_segment_udp en passant le pseudo entete en argument à la fonction
        higher_level = analyse_segment_udp(segment=packet[header_length:])
    else:
        higher_level = {"INFO": "UNKNOWN"}

    final_result = {"IP VERSION": [octets_version],
                    "IP HEADER LENGTH": [octets_header_length, header_length],
                    "IP TOS": [octets_type_of_service, bit_type_of_service],
                    "IP DTRC": [bit_dtrc, dtrc],
                    "IP PRIORITY D": [bit_priority_d, priority_d],
                    "IP PRIORITY T": [bit_priority_t, priority_t],
                    "IP PRIORITY R": [bit_priority_r, priority_r],
                    "IP PRIORITY C": [bit_priority_c, priority_c],
                    "IP PRECEDENCE": [bit_precedence, precedence],
                    "IP TOTAL LENGHT": [octets_header_length, total_length],
                    "IP IDENTIFIANT": [octets_identifier, identifier],
                    "IP R": [r],
                    "IP DF": [df],
                    "IP MF": [mf],
                    "IP FRAGMENT OFFSET": [fragment_offset],
                    "IP TTL": [octets_ttl, ttl],
                    "IP PROTOCOLE": [octets_protocole, protocole, dec_protocole],
                    "IP CHECKSUM": [header_checksum],
                    "IP ADDRESS IP SOURCE": [octets_ip_s, address_ip_source],
                    "IP ADDRESS IP DESTINATION": [octets_ip_d, address_ip_destination],
                    "IP OPTIONS": [length_options, octets_options]}

    for info in higher_level.keys():
        final_result[info] = higher_level[info]

    return final_result


def analyse_datagram_ipv6(packet: list):
    return {"IPV6": "TODO"}
