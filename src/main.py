import sys
from src.analyzer import *

# paramètre qui me permet de décider où écrire le résultat de l' analyse de la trame
print_in_file_or_cmdline = 0
# listes contenant des fichiers contenant les trames à analyser
list_files = []


def read_packets_file(name_file: str = "packet.txt") -> list:
    """
    Fonction qui me permet de lire une trame ethernet (contenu dans un fichier) et
    de retourner ses octets dans une liste

    :param name_file: nom du fichier à lire
    :return: liste des octets de la trame
    """

    list_packets = []
    offset_control = 0
    with open(name_file, "r") as file_packets:
        list_octets = []
        for line in file_packets:
            if not line:
                # print(">>>>> not line")
                list_packets.append(list_octets)
                offset_control = 0
            if line.isspace():
                # print(">>>>> isspace")
                list_packets.append(list_octets)
                offset_control = 0
                list_octets = []
            else:
                # print(f"offset_control = {offset_control}")
                # print(f"line = {line}", end='')
                list_octets_packet = line.split()
                # print(f"offset = {list_octets_packet[0]}\n")
                offset = convert_base_b_to_ten(number=list_octets_packet[0], base=16)
                # print(f"offset = {offset}")
                # Vérification de l'offset
                if offset == offset_control:
                    # si l'offset est valide, alors je prends les octets de la ligne lu
                    offset_control += 16
                    if len(list_octets_packet) == 1:
                        pass
                    elif len(list_octets_packet) > 17:
                        for indice in range(1, 17):
                            list_octets.append(list_octets_packet[indice])
                    else:
                        indice = 1
                        n_elem = len(list_octets_packet)
                        while (len(list_octets_packet[indice]) == 2) and (indice < n_elem - 2):
                            list_octets.append(list_octets_packet[indice])
                            indice += 1
                else:
                    # si l'offset n'est pas valide, alors j'ignore la ligne et je continue
                    pass
        list_packets.append(list_octets)
    return list_packets


def get_help(name_exec: str):
    print(f"Mode d'emploi:\n"
          f"\tSyntax: python3 {name_exec} [-help] [-printout=x] file_1 [file_n]\n\n"
          f"\t-help: Afficher le mode d'emploi du programme\n\n"
          f"\t-printout=x : Spécifie si afficher le résultat de l'analyse sur le terminal ou"
          f" l'enregistré dans un fichier:\n"
          f"\t\tx = 0 (default) : écrire le résultat sur le terminal\n"
          f"\t\tx = 1 : écrire le résultat dans un fichier (nom du fichier = res_analyse_'fileinput') sans"
          f" l'afficher sur le terminale\n"
          f"\t\tx = 2 : écrire le résultat sur le terminal et l'enregistré dans un fichier\n\n"
          f"\tfile_1 [file_n] : le(s) fichier(s) contenant la(les) trame(s) à analyser\n")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Si je n' ai passé aucun argument (help - printout - files ) en ligne de commande
        get_help(sys.argv[0])
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        elem = sys.argv[i]
        l_elem = elem.split("=")
        if elem == '-help':
            get_help(sys.argv[0])
        elif len(l_elem) > 1:
            if l_elem[0] == "-printout":
                try:
                    if int(l_elem[1]) == 1:
                        print_in_file_or_cmdline = 1
                    elif int(l_elem[1]) == 2:
                        print_in_file_or_cmdline = 2
                    else:
                        print_in_file_or_cmdline = 0
                except Exception as e:
                    print_in_file_or_cmdline = 0
                    print("Bad value of argument 'printout': default value = 0")
        else:
            list_files.append(elem)

    for file_frame in list_files:
        # read_packets_file : renvoit la liste contenant les octets de la trame
        packets = read_packets_file(name_file=file_frame)
        info_packets = ""
        for packet in packets:
            # get_info_trame : renvoit les informations contenu dans la trame sous le format wireshark
            if len(packet) > 1:
                info_packets += get_info_trame(frame=packet) + "\n\n\n"

        if print_in_file_or_cmdline == 0:
            print(info_packets)
        elif print_in_file_or_cmdline == 1:
            with open('res_analyse_' + file_frame, 'w') as f:
                f.write(info_packets)
        else:
            print(info_packets)
            with open('res_analyse_' + file_frame, 'w') as f:
                f.write(info_packets)
