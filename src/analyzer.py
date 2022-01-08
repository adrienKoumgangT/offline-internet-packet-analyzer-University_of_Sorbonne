# from utils.utils import *
from src.couche_link.protocol_ethernet import *


def get_info_trame(frame: list) -> str:
    info_frame = analyse_frame_ethernet2(frame=frame)
    final_print = "Informations trame Ethernet:\n"
    final_print += f"\t-[Eth2] Adresse mac destination: 0x{info_frame['ETHERNET ADDRESS MAC DESTINATION'][0]}"\
                   f" ({info_frame['ETHERNET ADDRESS MAC DESTINATION'][1]})\n"
    final_print += f"\t-[Eth2] Adresse mac source: 0x{info_frame['ETHERNET ADDRESS MAC SOURCE ETHERNET'][0]}" \
                   f" ({info_frame['ETHERNET ADDRESS MAC SOURCE ETHERNET'][1]})\n"
    final_print += f"\t-[Eth2] Protocole ethernet: 0x{info_frame['ETHERNET PROTOCOLE'][0]}" \
                   f" ({info_frame['ETHERNET PROTOCOLE'][1]})\n"
    if "ETHERNET TRAILER" in info_frame.keys():
        final_print += f"\t-[Eth2] Trailer: {info_frame['ETHERNET TRAILER'][0]}\n"
    # final_print += f"\t-[Eth2] FCS: 0x{info_frame['ETHERNET FCS'][0]}\n"
    if info_frame['ETHERNET PROTOCOLE'][0] == "0800":
        final_print += f"\nNiveau supérieur: IPv4\n"
        final_print += f"\t-[IPv4] Version ip: 0x{info_frame['IP VERSION'][0]}\n"
        final_print += f"\t-[IPv4] Longueur de l'entete IP: 0x{info_frame['IP HEADER LENGTH'][0]}" \
                       f" soit {info_frame['IP HEADER LENGTH'][1]} octets\n"
        final_print += f"\t-[IPv4] ToS: 0x{info_frame['IP TOS'][0]} ({info_frame['IP TOS'][1]})\n"
        final_print += f"\t\t-[IPv4] {info_frame['IP PRECEDENCE'][0]}. .... : {info_frame['IP PRECEDENCE'][1]}\n"
        final_print += f"\t\t-[IPv4] ...{info_frame['IP DTRC'][0]}. : {info_frame['IP DTRC'][1]}\n"
        final_print += f"\t\t-[IPv4] ...{info_frame['IP PRIORITY D'][0]} .... : {info_frame['IP PRIORITY D'][1]}\n"
        final_print += f"\t\t-[IPv4] .... {info_frame['IP PRIORITY T'][0]}... : {info_frame['IP PRIORITY T'][1]}\n"
        final_print += f"\t\t-[IPv4] .... .{info_frame['IP PRIORITY R'][0]}.. : {info_frame['IP PRIORITY R'][1]}\n"
        final_print += f"\t\t-[IPv4] .... ..{info_frame['IP PRIORITY C'][0]}. : {info_frame['IP PRIORITY C'][1]}\n"
        final_print += f"\t-[IPv4] Longueur total: 0x{info_frame['IP TOTAL LENGHT'][0]}" \
                       f" soit {info_frame['IP TOTAL LENGHT'][1]} octets\n"
        final_print += f"\t-[IPv4] Identifiant: 0x{info_frame['IP IDENTIFIANT'][0]}" \
                       f" ({info_frame['IP IDENTIFIANT'][1]})\n"
        final_print += f"\t-[IPv4] DF: {info_frame['IP DF'][0]}, MF: {info_frame['IP MF'][0]}\n"
        final_print += f"\t-[IPv4] Fragment Offset: {info_frame['IP FRAGMENT OFFSET'][0]}\n"
        final_print += f"\t-[IPv4] TTL: 0x{info_frame['IP TTL'][0]}," \
                       f" soit {info_frame['IP TTL'][1]} sauts\n"
        final_print += f"\t-[IPv4] Protocole: 0x{info_frame['IP PROTOCOLE'][0]}" \
                       f" {info_frame['IP PROTOCOLE'][1]} ({info_frame['IP PROTOCOLE'][2]})\n"
        final_print += f"\t-[IPv4] Somme de controle: 0x{info_frame['IP CHECKSUM'][0]}\n"
        final_print += f"\t-[IPv4] Adresse IP source: 0x{info_frame['IP ADDRESS IP SOURCE'][0]}" \
                       f" soit {info_frame['IP ADDRESS IP SOURCE'][1]}\n"
        final_print += f"\t-[IPv4] Adresse IP destination: 0x{info_frame['IP ADDRESS IP DESTINATION'][0]}" \
                       f" soit {info_frame['IP ADDRESS IP DESTINATION'][1]}\n"
        if info_frame['IP OPTIONS'][0] > 0:
            final_print += f"\t-[IPv4] OPTIONS IP + PADDING: 0x{info_frame['IP OPTIONS'][1]}\n"

        if info_frame['IP PROTOCOLE'][2] == 1:
            pass

        elif info_frame['IP PROTOCOLE'][2] == 6:
            final_print += f"\nNiveau supérieur: TCP\n"
            final_print += f"\t-[TCP] Port Source: 0x{info_frame['TCP SOURCE PORT'][0]}" \
                           f" soit {info_frame['TCP SOURCE PORT'][1]}\n"
            final_print += f"\t-[TCP] Port Destination: 0x{info_frame['TCP DESTINATION PORT'][0]}" \
                           f" soit {info_frame['TCP DESTINATION PORT'][0]}\n"
            final_print += f"\t-[TCP] Numéro de séquence: 0x{info_frame['TCP SEQUENCE NUMBER'][0]}" \
                           f" ({info_frame['TCP SEQUENCE NUMBER'][1]})\n"
            final_print += f"\t-[TCP] Acquitement: 0x{info_frame['TCP ACKNOWLEDGEMENT NUMBER'][0]}" \
                           f" ({info_frame['TCP ACKNOWLEDGEMENT NUMBER'][1]})\n"
            final_print += f"\t-[TCP] Taille de l'entete: 0x{info_frame['TCP HEADER LENGTH'][0]}" \
                           f" ({info_frame['TCP HEADER LENGTH'][1]} octets)"
            final_print += f"\t-[TCP] Reservé: 0x{info_frame['TCP RESERVED'][0]}\n"
            final_print += f"\t-[TCP] Flag: 0x{info_frame['TCP FLAG'][0]}" \
                           f" ({info_frame['TCP FLAG'][1]})\n"
            final_print += f"\t\t- URG: {info_frame['TCP URG'][0]}.....\n"
            final_print += f"\t\t- ACK: .{info_frame['TCP ACK'][0]}....\n"
            final_print += f"\t\t- PSH: ..{info_frame['TCP PSH'][0]}...\n"
            final_print += f"\t\t- RST: ...{info_frame['TCP RST'][0]}..\n"
            final_print += f"\t\t- SYN: ....{info_frame['TCP SYN'][0]}.\n"
            final_print += f"\t\t- FIN: .....{info_frame['TCP FIN'][0]}\n"
            final_print += f"\t-[TCP] Somme de controle: 0x{info_frame['TCP CHECKSUM'][0]}\n"
            final_print += f"\t-[TCP] pointeur urgent: 0x{info_frame['TCP URGENT POINTER'][0]}\n"
            if "TCP OPTIONS" in info_frame.keys():
                final_print += f"\t-[TCP] Options tcp: 0x{info_frame['TCP OPTIONS'][0]}\n"
            final_print += f"\t-[TCP] next protocol: 0x{info_frame['TCP NEXT PROTOCOL'][0]}\n"

            if info_frame['TCP NEXT PROTOCOL'][0] == "FTP":
                # TODO: FTP
                pass
            elif info_frame['TCP NEXT PROTOCOL'][0] == "HTTP":
                # TODO: HTTP
                pass
            else:
                final_print += f"\t-[TCP] DATA: {info_frame['TCP DATA']}\n"

        elif info_frame['IP PROTOCOLE'][2] == 17:
            final_print += f"\nNiveau supérieur: UDP\n"
            final_print += f"\t-[UDP] Port Source: 0x{info_frame['UDP PORT SOURCE'][0]}" \
                           f" soit {info_frame['UDP PORT SOURCE'][1]}\n"
            final_print += f"\t-[UDP] Port Destination: 0x{info_frame['UDP PORT DESTINATION'][0]}" \
                           f" soit {info_frame['UDP PORT DESTINATION'][1]}\n"
            final_print += f"\t-[UDP] Longueur total du datagram UDP: 0x{info_frame['UDP LENGTH'][0]}" \
                           f" ({info_frame['UDP LENGTH'][1]} octets)\n"
            final_print += f"\t-[UDP] Somme de controle: 0x{info_frame['UDP CHECKSUM'][0]}\n"
            if "UDP DATA" in info_frame.keys():
                final_print += f"\t-[UDP] Données: 0x{info_frame['UDP DATA']}\n"

            if info_frame['UDP NEXT PROTOCOLE'][0] == "DNS":
                final_print += f"\nNiveau supérieur: DNS\n"
                final_print += f"\t-[DNS] Id Transaction: 0x{info_frame['DNS QUERY ID'][0]}" \
                               f" ({info_frame['DNS QUERY ID'][1]})\n"
                final_print += f"\t-[DNS] Flags: 0x{info_frame['DNS FLAGS'][0]}" \
                               f" : {info_frame['DNS FLAGS'][1]}\n"
                final_print += f"\t\t-[DNS] {info_frame['DNS QR'][0]}... .... .... .... :" \
                               f" {info_frame['DNS QR'][1]}\n"
                final_print += f"\t\t-[DNS] .{info_frame['DNS OPERATION CODE'][0]} ... .... .... :" \
                               f" {info_frame['DNS OPERATION CODE'][1]}\n"
                final_print += f"\t\t-[DNS] .... .{info_frame['DNS AA'][0]}.. .... .... :" \
                               f" {info_frame['DNS AA'][1]}\n"
                final_print += f"\t\t-[DNS] .... ..{info_frame['DNS TC'][0]}. .... .... :" \
                               f" {info_frame['DNS TC'][0]}\n"
                final_print += f"\t\t-[DNS] .... .... {info_frame['DNS RA'][0]}... .... :" \
                               f" {info_frame['DNS RA'][1]}\n"
                final_print += f"\t\t-[DNS] .... .... .{info_frame['DNS Z'][0]} .... :" \
                               f" {info_frame['DNS Z'][1]}\n"
                final_print += f"\t\t-[DNS] .... .... .... {info_frame['DNS R CODE'][0]} :" \
                               f" {info_frame['DNS R CODE'][1]} ({info_frame['DNS R CODE'][2]})\n"
                final_print += f"\t-[DNS] Nombre de question: 0x{info_frame['DNS QUESTION COUNT'][0]}" \
                               f" soit {info_frame['DNS QUESTION COUNT'][1]}\n"
                final_print += f"\t-[DNS] Nombre de réponse: 0x{info_frame['DNS ANSWER COUNT'][0]}" \
                               f" soit {info_frame['DNS ANSWER COUNT'][1]}\n"
                final_print += f"\t-[DNS] Nombre d'authority: 0x{info_frame['DNS AUTHORITY COUNT'][0]}" \
                               f" soit {info_frame['DNS AUTHORITY COUNT'][1]}\n"
                final_print += f"\t-[DNS] Nombre d'additional RR: 0x{info_frame['DNS RECORD COUNT'][0]}" \
                               f" soit {info_frame['DNS RECORD COUNT'][1]}\n"

                result_inter_request = info_frame['DNS REQUEST']
                final_print += f"\t-[DNS] QUERY\n"
                for i in range(info_frame['DNS QUESTION COUNT'][1]):
                    final_print += f"\t\t-[DNS] Nom: 0x{result_inter_request['NAME ADDRESS'][i][0]}" \
                                   f" soit {result_inter_request['NAME ADDRESS'][i][1]}\n"
                    final_print += f"\t\t-[DNS] Taille du nom: {result_inter_request['LENGTH'][i]}\n"
                    final_print += f"\t\t-[DNS] Taille label: {result_inter_request['LABEL COUNT'][i]}\n"
                    final_print += f"\t\t-[DNS] Type: 0x{result_inter_request['TYPE'][i][0]} :" \
                                   f" {result_inter_request['TYPE'][i][2]}" \
                                   f" ({result_inter_request['TYPE'][i][1]})\n"
                    final_print += f"\t\t-[DNS] Class: 0x{result_inter_request['CLASS'][i][0]} :" \
                                   f" {result_inter_request['CLASS'][i][2]}" \
                                   f" ({result_inter_request['CLASS'][i][1]})\n\n"

                if info_frame['DNS ANSWER COUNT'][1] > 0:
                    final_print += f"\t-[DNS] ANSWER\n"
                    result_inter_answer = info_frame['DNS ANSWER']
                    for i in range(info_frame['DNS ANSWER COUNT'][1]):
                        final_print += f"\t\t-[DNS] Nom: {result_inter_answer['NAME ADDRESS'][i]}\n"
                        final_print += f"\t\t-[DNS] Type: 0x{result_inter_answer['TYPE'][i][0]} :" \
                                       f" {result_inter_answer['TYPE'][i][2]}" \
                                       f" ({result_inter_answer['TYPE'][i][1]})\n"
                        final_print += f"\t\t-[DNS] Class: 0x{result_inter_answer['CLASS'][i][0]} :" \
                                       f" {result_inter_answer['CLASS'][i][2]}" \
                                       f" ({result_inter_answer['CLASS'][i][1]})\n"
                        final_print += f"\t\t-[DNS] Durée de vie: 0x{result_inter_answer['TTL'][i][0]} soit" \
                                       f" {result_inter_answer['TTL'][i][1]} secondes" \
                                       f" ({result_inter_answer['TTL'][i][2]})\n"
                        final_print += f"\t\t-[DNS] Taille des données : 0x{result_inter_answer['LENGTH DATA'][i][0]}" \
                                       f" soit {result_inter_answer['LENGTH DATA'][i][1]}\n"
                        data = "".join(result_inter_answer['DATA'][i][0])
                        data_value = get_str_ascii(my_str=data)
                        final_print += f"\t\t-[DNS] DATA : 0x{data}  ({data_value})\n\n"

                # TODO: AUTHORITY

                if info_frame['DNS RECORD COUNT'][1] > 0:
                    final_print += f"\t-[DNS] RECORD\n"
                    result_inter_addl = info_frame['DNS RECORD']
                    for i in range(info_frame['DNS RECORD COUNT'][1]):
                        final_print += f"\t\t-[DNS] Nom: {result_inter_addl['NAME ADDRESS'][i]}\n"
                        final_print += f"\t\t-[DNS] Type: 0x{result_inter_addl['TYPE'][i][0]} :" \
                                       f" {result_inter_addl['TYPE'][i][2]}" \
                                       f" ({result_inter_addl['TYPE'][i][1]})\n"
                        final_print += f"\t\t-[DNS] Class: 0x{result_inter_addl['CLASS'][i][0]} :" \
                                       f" {result_inter_addl['CLASS'][i][2]}" \
                                       f" ({result_inter_addl['CLASS'][i][1]})\n"
                        final_print += f"\t\t-[DNS] Durée de vie: 0x{result_inter_addl['TTL'][i][0]} soit" \
                                       f" {result_inter_addl['TTL'][i][1]} secondes" \
                                       f" ({result_inter_addl['TTL'][i][2]})\n"
                        final_print += f"\t\t-[DNS] Taille des données : 0x{result_inter_addl['LENGTH DATA'][i][0]}" \
                                       f" soit {result_inter_addl['LENGTH DATA'][i][1]}\n"
                        final_print += f"\t\t-[DNS] DATA : 0x{result_inter_addl['DATA'][i][0]}\n\n"

            elif info_frame['UDP NEXT PROTOCOLE'][0] == "DHCP":
                final_print += f"\nNiveau supérieur: DHCP\n"
                final_print += f"\t-[DHCP] Type du message: 0x{info_frame['DHCP OP'][0]}" \
                               f" soit {info_frame['DHCP OP'][1]} ({info_frame['DHCP OP'][2]})\n"
                final_print += f"\t-[DHCP] Type de l'adresse MAC: 0x{info_frame['DHCP HTYPE'][0]}" \
                               f" soit {info_frame['DHCP HTYPE'][1]} ({info_frame['DHCP HTYPE'][2]})\n"
                final_print += f"\t-[DHCP] Longueur de l'adresse MAC: 0x{info_frame['DHCP HLEN'][0]}" \
                               f" soit {info_frame['DHCP HLEN'][1]} octets\n"
                final_print += f"\t-[DHCP] Compteur de saut: 0x{info_frame['DHCP HOPS'][0]}" \
                               f" soit {info_frame['DHCP HOPS'][1]} sauts\n"
                final_print += f"\t-[DHCP] Identifiant de la transaction: 0x{info_frame['DHCP XID'][0]}" \
                               f" ({info_frame['DHCP XID'][1]})\n"
                final_print += f"\t-[DHCP] Temps écoulé depuis le début de la transaction:" \
                               f" 0x{info_frame['DHCP SECS'][0]}" \
                               f" soit {info_frame['DHCP SECS'][1]}\n"
                final_print += f"\t-[DHCP] Flags: 0x{info_frame['DHCP FLAGS'][0]}" \
                               f" ({info_frame['DHCP FLAGS'][1]})\n"
                final_print += f"\t-[DHCP] Client IP Address: 0x{info_frame['DHCP CLIENT IP ADDRESS'][0]}" \
                               f" soit {info_frame['DHCP CLIENT IP ADDRESS'][1]}\n"
                final_print += f"\t-[DHCP] Your IP Address: 0x{info_frame['DHCP YOUR IP ADDRESS'][0]}" \
                               f" soit {info_frame['DHCP YOUR IP ADDRESS'][1]}\n"
                final_print += f"\t-[DHCP] Server IP Address: 0x{info_frame['DHCP SERVER IP ADDRESS'][0]}" \
                               f" soit {info_frame['DHCP SERVER IP ADDRESS'][1]}\n"
                final_print += f"\t-[DHCP] Gateway IP Address: 0x{info_frame['DHCP GATEWAY IP ADDRESS'][0]}" \
                               f" soit {info_frame['DHCP GATEWAY IP ADDRESS'][1]}\n"
                final_print += f"\t-[DHCP] Adresse MAC du client: 0x{info_frame['DHCP MAC ADDRESS'][0]}" \
                               f" soit {info_frame['DHCP MAC ADDRESS'][1]}\n"
                final_print += f"\t-[DHCP] Adresse MAC PADDING 0x{info_frame['DHCP MAC ADDRESS PADDING'][0]}\n"
                final_print += f"\t-[DHCP] Adresse Optionelle d'un serveur:" \
                               f" 0x{info_frame['DHCP SNAME'][0]} ({info_frame['DHCP SNAME'][1]})" \
                               f" ({info_frame['DHCP SNAME'][2]})\n"
                final_print += f"\t-[DHCP] Nom du fichier de Démarrage:" \
                               f" {info_frame['DHCP SNAME'][0]} ({info_frame['DHCP SNAME'][1]})" \
                               f" ({info_frame['DHCP SNAME'][2]})\n"
                result_options = info_frame['DHCP OPTIONS']
                list_code_options = result_options[0]
                list_options = result_options[1]
                list_label = result_options[2]
                for i in range(len(list_code_options)):
                    options = list_options[i]
                    if list_code_options[i] != 255:
                        final_print += f"\t-[DHCP] Option ({list_code_options[i]}) {list_label[i]}\n"
                        final_print += f"\t\t-[DHCP] Length : 0x{options[0]} soit {options[1]}\n"
                    if list_code_options[i] == 1:
                        final_print += f"\t\t-[DHCP] {list_label[i]} : 0x{options[2]} soit {options[3]}\n"
                    elif list_code_options[i] == 50:
                        final_print += f"\t\t-[DHCP] {list_label[i]} : 0x{options[2]} soit {options[3]}\n"
                    elif list_code_options[i] == 51:
                        final_print += f"\t\t-[DHCP] {list_label[i]} : 0x{options[2]} soit {options[3]}s" \
                                       f" ({options[4]})\n"
                    elif list_code_options[i] == 52:
                        final_print += f"\t\t-[DHCP] {list_label[i]} : 0x{options[2]} soit {options[3]}" \
                                       f" ({options[4]})\n"
                    elif list_code_options[i] == 53:
                        final_print += f"\t\t-[DHCP] {list_label[i]}: 0x{options[2]} soit {options[4]}" \
                                       f" ({options[3]})\n"
                    elif list_code_options[i] == 54:
                        final_print += f"\t\t-[DHCP] {list_label[i]}: 0x{options[2]} soit {options[3]}\n"
                    elif list_code_options[i] == 55:
                        list_item = options[2]
                        list_item_info = options[3]
                        for indice in range(len(list_item)):
                            final_print += f"\t\t\t-[DHCP] {list_label[i]} Item: ({list_item[indice]})" \
                                           f" {list_item_info[indice]}\n"
                    elif list_code_options[i] == 58:
                        final_print += f"\t\t-[DHCP] {list_label[i]}: 0x{options[2]} soit {options[3]}s" \
                                       f" ({options[4]})\n"
                    elif list_code_options[i] == 59:
                        final_print += f"\t\t-[DHCP] {list_label[i]}: 0x{options[2]} soit {options[3]}s" \
                                       f" ({options[4]})\n"
                    elif list_code_options[i] == 61:
                        final_print += f"\t\t-[DHCP] Hardware type: {options[4]} (0x{options[2]})\n"
                        final_print += f"\t\t-[DHCP] Client MAC address: {options[5]}\n"
                    elif list_code_options[i] == 255:
                        final_print += f"\t-[DHCP] Option: (255) End\n"
                        final_print += f"\t\t-[DHCP] Option End: 255\n"
                        final_print += f"\t-[DHCP] END PADDING : 0x{options[0]}\n"
                    else:
                        final_print += f"\t\t-[DHCP] OPTIONS : 0x{options[2]}\n"

            else:
                final_print += f"\nNiveau supérieur: INCONNU\n"

    elif info_frame['ETHERNET PROTOCOLE'][0] == "86DD":
        pass

    elif info_frame['ETHERNET PROTOCOLE'][0] == "0806":
        final_print += f"\nNiveau supérieur: ARP ({info_frame['ARP OPCODE'][2]})\n"
        final_print += f"\t-[ARP] Hardware type: 0x{info_frame['ARP HARDWARE TYPE'][0]} soit" \
                       f" {info_frame['ARP HARDWARE TYPE'][2]} ({info_frame['ARP HARDWARE TYPE'][1]})\n"
        final_print += f"\t-[ARP] Protocol type: 0x{info_frame['ARP PROTOCOL TYPE'][0]} soit" \
                       f" {info_frame['ARP PROTOCOL TYPE'][1]}\n"
        final_print += f"\t-[ARP] Hardware size: 0x{info_frame['ARP HARDWARE SIZE'][0]} soit" \
                       f" {info_frame['ARP HARDWARE SIZE'][1]}\n"
        final_print += f"\t-[ARP] Protocol size: 0x{info_frame['ARP PROTOCOL SIZE'][0]} soit" \
                       f" {info_frame['ARP PROTOCOL SIZE'][1]}\n"
        final_print += f"\t-[ARP] Opcode: 0x{info_frame['ARP OPCODE'][0]} soit {info_frame['ARP OPCODE'][2]}" \
                       f" ({info_frame['ARP OPCODE'][1]})\n"
        final_print += f"\t-[ARP] Sender MAC address: 0x{info_frame['ARP SOURCE MAC ADDRESS'][0]}" \
                       f" ({info_frame['ARP SOURCE MAC ADDRESS'][1]})\n"
        final_print += f"\t-[ARP] Sender IP address: 0x{info_frame['ARP SOURCE IP ADDRESS'][0]}" \
                       f" ({info_frame['ARP SOURCE IP ADDRESS'][1]})\n"
        final_print += f"\t-[ARP] Target MAC address: 0x{info_frame['ARP DESTINATION MAC ADDRESS'][0]}" \
                       f" ({info_frame['ARP DESTINATION MAC ADDRESS'][1]})\n"
        final_print += f"\t-[ARP] Target IP address: 0x{info_frame['ARP DESTINATION IP ADDRESS'][0]}" \
                       f" ({info_frame['ARP DESTINATION IP ADDRESS'][1]})\n"

    elif info_frame['ETHERNET PROTOCOLE'][0] == "0835":
        pass
    elif info_frame['ETHERNET PROTOCOLE'][0] == "80D5":
        pass
    else:
        final_print += f"\t- UNKNOWN PROTOCOLE\n"

    return final_print
