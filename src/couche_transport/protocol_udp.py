# from utils.utils import *
from src.couche_application.protocol_dhcp import *
from src.couche_application.protocol_dns import *
# from src.couche_application.protocol_http import *
# from src.couche_application.protocol_imap import *


# UDP: User Datagram Protocol
# TODO: ajouter en paramètre le pseudo-entete pour le controle d'erreur avec le checksum
def analyse_segment_udp(segment: list) -> dict:
    """
    Fonction qui me permet d'analyser une trame UDP

    :param segment: list contenant les octets du protocole UDP
    :return: les informations contenu dans la trame UDP
    """

    # Port Source: il s' agit du numéro de port correspondant à l' application émettrice du segment UDP
    octets_port_source = "".join(segment[0:2])
    port_source = convert_base_b_to_ten(number=octets_port_source, base=16)

    # Port Destination: ce champ contient le port correspondant à l' application de la machine destinataire
    # à laquelle on s' adresse
    octets_port_destination = "".join(segment[2:4])
    port_destination = convert_base_b_to_ten(number=octets_port_destination, base=16)

    # Longueur: il indique la longueur totale du datagram UDP (en-tete et données)
    # La longueur minimal est donc de 8 octets (taille de l' en-tete)
    octets_length_udp = "".join(segment[4:6])
    length_udp = convert_base_b_to_ten(number=octets_length_udp, base=16)

    octets_check_sum = "".join(segment[6:8])
    data_udp = segment[8:]

    if (port_source == 53) or (port_destination == 53):
        next_protocole = "DNS"
        result_upper_level = analyse_datagram_dns(datagram=data_udp)
    elif (port_source == 67) or (port_destination == 67):
        next_protocole = "DHCP"
        result_upper_level = analyse_datagram_dhcp(datagram=data_udp)
    else:
        next_protocole = "DATA"
        result_upper_level = {"UDP DATA": "".join(data_udp)}

    final_result = {"UDP PORT SOURCE": [octets_port_source, port_source],
                    "UDP PORT DESTINATION": [octets_port_destination, port_destination],
                    "UDP LENGTH": [octets_length_udp, length_udp],
                    "UDP CHECKSUM": [octets_check_sum],
                    "UDP NEXT PROTOCOLE": [next_protocole]}

    for key in result_upper_level.keys():
        final_result[key] = result_upper_level[key]

    return final_result
