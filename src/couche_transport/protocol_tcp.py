# from utils.utils import *
from src.couche_application.protocol_ftp import *
from src.couche_application.protocol_http import *


# TCP: Transmission Control Protocol
def analyse_segment_tcp(segment):
    # Le champ Port source et destination: Ils identifient les programmes d' application
    octets_port_source = "".join(segment[0:2])
    port_source = convert_base_b_to_ten(number=octets_port_source, base=16)
    octets_port_destination = "".join(segment[2:4])
    port_destination = convert_base_b_to_ten(number=octets_port_destination, base=16)

    # Le champ numéro de séquence: il indique le numéro du premier octets transmis dans le segment
    octets_sequence_number = "".join(segment[4:8])
    sequence_number = convert_base_b_to_ten(number=octets_sequence_number, base=16)

    # Le champ Acquittement: il indique le numéro du prochain octet attendu par l' émetteur de ce message
    octets_acknowledgment_number = "".join(segment[8:12])
    acknowledgment_number = convert_base_b_to_ten(octets_acknowledgment_number, base=16)

    octets_hl_reserved_flag = "".join(segment[12:14])
    bit_hl_reserved_flag = convert_base_b1_to_b2(octets_hl_reserved_flag, base1=16, base2=2)
    bit_hl_reserved_flag = ("0" * (16 - len(bit_hl_reserved_flag))) + bit_hl_reserved_flag
    # Le champ hl entete: Il indique, sur 4 bits, la taille en mot de 32 bits de l'entete.
    bit_header_length = bit_hl_reserved_flag[0:4]
    bit_reserved = bit_hl_reserved_flag[4:10]
    octets_reserved = convert_base_b1_to_b2(number=bit_reserved, base1=2, base2=16)
    bit_flag = bit_hl_reserved_flag[10:]
    octets_flag = convert_base_b1_to_b2(number=bit_flag, base1=2, base2=16)
    header_length = convert_base_b_to_ten(number=bit_header_length, base=2)
    octets_header_length = convert_base_ten_to_b(number=header_length, base=16)
    # URG: Validation de la valeur du champ "pointeur message urgent"
    urg = bit_flag[0]
    # ACK: La valeur du champ "acquittement" peut etre prise en compte
    ack = bit_flag[1]
    # PSH: Les données doivent etre immédiatement transmises à la couche supérieure
    psh = bit_flag[2]
    # RST: Fermeture de la connexion à cause d' une erreur irrécupérable
    rst = bit_flag[3]
    # SYN: Ouverture de la connexion
    syn = bit_flag[4]
    # FIN: Fin de connexion (plus de données à émettre)
    fin = bit_flag[5]

    octets_checksum = "".join(segment[14:16])
    octets_urgent_pointer = "".join(segment[16:18])
    octets_options = "".join(segment[18:24])
    octets_data = segment[24:]

    final_result = {"TCP SOURCE PORT": [octets_port_source, port_source],
                    "TCP DESTINATION PORT": [octets_port_destination, port_destination],
                    "TCP SEQUENCE NUMBER": [octets_sequence_number, sequence_number],
                    "TCP ACKNOWLEDGEMENT NUMBER": [octets_acknowledgment_number, acknowledgment_number],
                    "TCP HEADER LENGTH": [octets_header_length, header_length],
                    "TCP RESERVED": [octets_reserved],
                    "TCP FLAG": [octets_flag, bit_flag],
                    "TCP URG": [urg],
                    "TCP ACK": [ack],
                    "TCP PSH": [psh],
                    "TCP RST": [rst],
                    "TCP SYN": [syn],
                    "TCP FIN": [fin],
                    "TCP CHECKSUM": [octets_checksum],
                    "TCP URGENT POINTER": [octets_urgent_pointer],
                    "TCP OPTIONS": [octets_options]}

    if 21 in {port_source, port_destination}:
        next_protocol = "FTP"
        result_analyse_data = analyse_message_ftp(message=octets_data)
    elif 80 in {port_source, port_destination}:
        next_protocol = "HTTP"
        result_analyse_data = analyse_message_http(message=octets_data)
    else:
        next_protocol = "UNKNOWN"
        result_analyse_data = {"TCP DATA": [octets_data]}

    final_result["TCP NEXT PROTOCOL"] = [next_protocol]
    for k in result_analyse_data.keys():
        final_result[k] = result_analyse_data[k]

    return final_result
