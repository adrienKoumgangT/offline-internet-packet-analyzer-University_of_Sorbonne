# from utils.utils import *
from src.couche_network.protocol_ip import *
from src.couche_network.protocol_arp import *
from src.couche_network.protocol_appletalk import *
from src.couche_network.protocol_ibm import *
from src.couche_network.protocol_sercos import *
from src.couche_network.protocol_xns import *
from src.couche_network.protocol_vlan import *


def analyse_frame_ethernet(frame: list, type_frame=None) -> dict:
    """
    Analyse d'une trame Ethernet contenant le champ préambule, sfd et fcs

    :param frame: la list des octets représentants la trame Ethernet
    :param type_frame: le type de trame Ethernet: 2 ou 802.1Q

    :return: un dictionnaire contenant toutes les informations extraites de la trame

    """
    # Trame Ethernet: Préambule + SFD + Adresse destination + Adresse source + Protocole de couche + Champs de données
    #                               + FCS
    octets_preambule = frame[0:7]
    octets_sfd = frame[7]
    octets_fcs = frame[-4:]

    rest_frame_ethernet = frame[18:]
    rest_frame_ethernet.reverse()
    rest_frame_ethernet = rest_frame_ethernet[4:]
    rest_frame_ethernet.reverse()

    if type_frame is not None and type_frame == "802.1Q":
        result_analyse_ethernet = analyse_frame_ethernet802_1q(frame=rest_frame_ethernet)
    else:
        result_analyse_ethernet = analyse_frame_ethernet2(frame=rest_frame_ethernet)

    final_result = {"ETHERNET PREAMBULE": [octets_preambule],
                    "ETHERNET SFD": [octets_sfd],
                    "ETHERNET FCS": [octets_fcs]}

    for info in result_analyse_ethernet.keys():
        final_result[info] = result_analyse_ethernet[info]

    return final_result


def analyse_frame_ethernet802_1q(frame: list):
    """
    Fonction qui me permet d' analyser une trame Ethernet2
    Ici la trame ethernet est prise dans préambule ni CRC

    :param frame: list contenant les octets à analyser
    :return: return un dictionnaire contenant les informations de la trame
    """

    # Trame Ethernet: Adresse destination + Adresse source + Protocole de couche + TPID + TCI + Champs de données
    # TCI = Priorité + CFI + VLAN ID

    bloc_ethernet = frame[0:18]
    # Destination address: est l'adresse physique (MAC) du destinataire de la trame
    octets_address_mac_destination = "".join(bloc_ethernet[0:6])
    address_mac_destination = ":".join(bloc_ethernet[0:6])
    # Source address: est l'adresse physique (MAX) de l'expéditeur de la trame
    octets_address_mac_source = "".join(bloc_ethernet[6:12])
    address_mac_source = ":".join(bloc_ethernet[6:12])

    # Le champ TPID détermine le type du tag, 0x8100 pour 802.1Q, ce champ est utilisé pour prévoir
    # des évolutions futures afin de pouvoir utiliser le principe du tagging pour différentes fonctionnalités.
    octets_tpid = "".join(bloc_ethernet[12:14])
    # Le champ TCI se décline en plusieurs éléments:
    # - Priorité: niveaux de priorité définis par l'IEEE 802.1P. Ce champ permet de réaliser une priorisation des flux.
    # - CFI: Ce bit permet de déterminer si le tag s'applique à une trame de type Ethernet ou Token-Ring.
    # VID: VLAN identifier. C'est l'identifiant du VLAN.
    octets_tci = "".join(bloc_ethernet[14:16])
    bit_tci = convert_base_b1_to_b2(number=octets_tci, base1=16, base2=2)
    if len(bit_tci) < 16:
        bit_tci = ("0" * (16 - len(bit_tci))) + bit_tci
    bit_priority = bit_tci[0:3]
    bit_cfi = bit_tci[3]
    bit_vlan_id = bit_tci[4:]

    # Protocol: Indique le protocole de niveau supérieur encapsulé dans le champ Data de la trame.
    protocole_ethernet = "".join(bloc_ethernet[16:18])
    protocole_ethernet = protocole_ethernet.upper()

    packet = frame[14:]
    if protocole_ethernet == "0800":
        # DoD Internet (Datagramme IP)
        protocole = "IPv4"
        result_analyse_packet = analyse_datagram_ipv4(packet=packet)
    elif protocole_ethernet == "86DD":
        protocole = "IPv6"
        result_analyse_packet = analyse_datagram_ipv6(packet=packet)
    elif protocole_ethernet == "0806":
        protocole = "ARP"
        result_analyse_packet = analyse_packet_arp(packet=packet)
    elif protocole_ethernet == "8035":
        protocole = "RARP"
        result_analyse_packet = analyse_packet_rarp(packet=packet)
    elif protocole_ethernet == "8098":
        protocole = "Appletalk"
        result_analyse_packet = analyse_packet_appletalk(packet=packet)
    elif protocole_ethernet == "80D5":
        protocole = "IBM SNA Service on Ether"
        result_analyse_packet = analyse_packet_ibm(packet=packet)
    elif protocole_ethernet == "88CD":
        protocole = "SERCOS III"
        result_analyse_packet = analyse_packet_sercos_iii(packet=packet)
    elif protocole_ethernet == "0600":
        protocole = "XNS"
        result_analyse_packet = analyse_packet_xns(packet=packet)
    elif protocole_ethernet == "8100":
        protocole = "VLAN"
        result_analyse_packet = analyse_packet_vlan(packet=packet)
    else:
        protocole = "UNKNOWN"
        result_analyse_packet = "BAD PACKET"

    final_result = {"ETHERNET ADDRESS MAC DESTINATION": [octets_address_mac_destination, address_mac_destination],
                    "ETHERNET ADDRESS MAC SOURCE ETHERNET": [octets_address_mac_source, address_mac_source],
                    "ETHERNET PROTOCOLE": [protocole_ethernet, protocole],
                    "ETHERNET TPID": [octets_tpid],
                    "ETHERMET TCI": [octets_tci, bit_tci, bit_priority, bit_cfi, bit_vlan_id]}

    for info in result_analyse_packet.keys():
        final_result[info] = result_analyse_packet[info]

    return final_result


def analyse_frame_ethernet2(frame: list) -> dict:
    """
    Fonction qui me permet d' analyser une trame Ethernet2
    Ici la trame ethernet est prise dans préambule ni CRC

    :param frame: list contenant les octets à analyser
    :return: return un dictionnaire contenant les informations de la trame
    """

    # Trame Ethernet: Adresse destination + Adresse source + Protocole de couche + Champs de données

    bloc_ethernet = frame[0:14]
    # Destination address: est l'adresse physique (MAC) du destinataire de la trame
    octets_address_mac_destination = "".join(bloc_ethernet[0:6])
    address_mac_destination = ":".join(bloc_ethernet[0:6])
    # Source address: est l'adresse physique (MAX) de l'expéditeur de la trame
    octets_address_mac_source = "".join(bloc_ethernet[6:12])
    address_mac_source = ":".join(bloc_ethernet[6:12])

    # Protocol: Indique le protocole de niveau supérieur encapsulé dans le champ Data de la trame.
    protocole_ethernet = "".join(bloc_ethernet[12:14])
    protocole_ethernet = protocole_ethernet.upper()

    packet = frame[14:]
    if protocole_ethernet == "0800":
        # DoD Internet (Datagramme IP)
        protocole = "IPv4"
        result_analyse_packet = analyse_datagram_ipv4(packet=packet)
    elif protocole_ethernet == "86DD":
        protocole = "IPv6"
        result_analyse_packet = analyse_datagram_ipv6(packet=packet)
    elif protocole_ethernet == "0806":
        protocole = "ARP"
        result_analyse_packet = analyse_packet_arp(packet=packet)
    elif protocole_ethernet == "8035":
        protocole = "RARP"
        result_analyse_packet = analyse_packet_rarp(packet=packet)
    elif protocole_ethernet == "8098":
        protocole = "Appletalk"
        result_analyse_packet = analyse_packet_appletalk(packet=packet)
    elif protocole_ethernet == "80D5":
        protocole = "IBM SNA Service on Ether"
        result_analyse_packet = analyse_packet_ibm(packet=packet)
    elif protocole_ethernet == "88CD":
        protocole = "SERCOS III"
        result_analyse_packet = analyse_packet_sercos_iii(packet=packet)
    elif protocole_ethernet == "0600":
        protocole = "XNS"
        result_analyse_packet = analyse_packet_xns(packet=packet)
    elif protocole_ethernet == "8100":
        protocole = "VLAN"
        result_analyse_packet = analyse_packet_vlan(packet=packet)
    else:
        protocole = "UNKNOWN"
        result_analyse_packet = "BAD PACKET"

    final_result = {"ETHERNET ADDRESS MAC DESTINATION": [octets_address_mac_destination, address_mac_destination],
                    "ETHERNET ADDRESS MAC SOURCE ETHERNET": [octets_address_mac_source, address_mac_source],
                    "ETHERNET PROTOCOLE": [protocole_ethernet, protocole]}

    for info in result_analyse_packet.keys():
        final_result[info] = result_analyse_packet[info]

    return final_result
