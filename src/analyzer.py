from utils.utils import *


def get_cidr(ad_ip: str, mask: str) -> str:
    """
    méthode qui a partir de l'IP et du masque
    renvoie la notation CIDR
    """
    s = mask.split(".")
    one = 0
    for elem in s:
        if elem != 0:
            r = convert_base_ten_to_b(number=int(elem), base=2)
            one += r.count("1")
    return ad_ip + "/" + str(one)


def get_ip_masque(cidr: str) -> tuple:
    """
    méthode qui a partir du CIDR retourne l' ip et le masque
    """
    if not cidr:
        return ()
    ip_mask = cidr.split("/")
    final_ip = ip_mask[0]
    mask = int(ip_mask[1])
    if mask == 32:
        return final_ip, "255.255.255.255"
    if mask == 0:
        return final_ip, "0.0.0.0"
    final_mask = ""
    # premier set de bit 255.-.-.-
    for i in range(0, 4):
        if mask > 8:
            final_mask += "255"
            mask -= 8
        elif mask != 0:
            n = "1." * mask
            n += "0." * (8 - mask)
            n = n[:len(n) - 1]
            num = convert_base_b_to_ten(number=n, base=2)
            final_mask += str(num)
            mask = 0
        elif mask == 0:
            final_mask += "0"
        if i != 3:
            final_mask = final_mask + "."
    return final_ip, final_mask


def num_machine_cidr(cidr: str) -> int:
    masque = int(cidr.split("/")[1])
    nb = (2 ** (32 - masque)) - 2
    return nb


def num_machine_ip_masque(ad_ip: str, mask: str) -> int:
    cidr = get_cidr(ad_ip=ad_ip, mask=mask)
    return num_machine_cidr(cidr=cidr)


def inverse_nombre(number: int) -> int:
    if number == 255:
        return 0
    if number == 0:
        return 255
    nb = convert_base_ten_to_b(number=number, base=2)
    nbs = nb.split(".")
    ni = []
    for bit in nbs:
        if bit == "0":
            ni.append("1")
        else:
            ni.append("0")
    b = ".".join(ni)
    return convert_base_b_to_ten(b, 2)


def inverse_masque(masque: str) -> str:
    m = masque.split(".")
    s = []
    for elem in m:
        s.append(str(inverse_nombre(number=int(elem))))
    return ".".join(s)


def get_subnet_address(cidr: str) -> str:
    (ip, mask) = get_ip_masque(cidr=cidr)
    list_ip = ip.split(".")
    list_mask = mask.split(".")
    subnet = []
    for i in range(0, 4):
        subnet.append(str(int(list_ip[i]) & int(list_mask[i])))
    return ".".join(subnet)


def get_address_ip(a_d: list) -> str:
    if len(a_d) != 4:
        return ""
    ip1 = a_d[0]
    ip2 = a_d[1]
    ip3 = a_d[2]
    ip4 = a_d[3]
    return ".".join([str(convert_base_b_to_ten(number=ip1, base=16)),
                    str(convert_base_b_to_ten(number=ip2, base=16)),
                    str(convert_base_b_to_ten(number=ip3, base=16)),
                    str(convert_base_b_to_ten(number=ip4, base=16))])


def calcul_checksum(data_checksum):
    len_data_checksum = len(data_checksum)
    if len_data_checksum % 2 != 0:
        return 0
    else:
        final_sum = 0
        for i in range(0, len_data_checksum, 2):
            octets_data = "".join(data_checksum[i:i+2])
            dec_data = convert_base_b_to_ten(number=octets_data, base=16)
            final_sum += dec_data
        bit_checksum = convert_base_ten_to_b(number=final_sum, base=2)
        if len(bit_checksum) > 16:
            first_part = bit_checksum[-16:]
            second_part = bit_checksum[0:len(bit_checksum)-16]
            dec_first_part = convert_base_b_to_ten(number=first_part, base=2)
            dec_second_part = convert_base_b_to_ten(number=second_part, base=2)
            checksum = convert_base_ten_to_b(number=dec_first_part+dec_second_part, base=16)
        else:
            checksum = convert_base_ten_to_b(number=final_sum, base=16)
        return checksum


def get_flags_and_fragment_offset(flags_frag: list) -> list:
    ff = "".join(flags_frag[0:2])
    b_ff = convert_base_b1_to_b2(number=ff, base1=16, base2=2)
    if len(b_ff) < 16:
        b_ff = ("0" * (16 - len(b_ff))) + b_ff
    return [b_ff[0], b_ff[1], b_ff[2], convert_base_b_to_ten(number="".join(b_ff[3:]), base=2)]


def analyse_flags_dns(flags):
    octets_flags = flags
    bit_flags = convert_base_b1_to_b2(number=octets_flags, base1=16, base2=2)
    bit_flags = ("0" * (16 - len(bit_flags))) + bit_flags

    bit_q_or_r = bit_flags[0]
    if bit_q_or_r == "0":
        q_or_r = "REQUEST"
    else:
        q_or_r = "ANSWER"

    bit_operation_code = "".join(bit_flags[1:5])
    op_code = convert_base_b_to_ten(number=bit_operation_code, base=2)
    if op_code == 0:
        operation_code = "QUERY"
    elif op_code == 1:
        operation_code = "IQUERY"
    elif op_code == 2:
        operation_code = "STATUS"
    else:
        operation_code = "RESERVATED"

    bit_aa = bit_flags[5]
    if bit_aa == "0":
        aa = "NOT AUTHORITATIVE ANSWER"
    else:
        aa = "AUTHORITATIVE ANSWER"

    bit_tc = bit_flags[6]
    if bit_tc == "0":
        tc = "MESSGAE NOT TRUNCATED"
    else:
        tc = "MESSGE TRUNCATED"

    bit_rd = bit_flags[7]
    if bit_rd == "0":
        rd = "ASK RECURSIVENESS"
    else:
        rd = "NOT REQUIRE RECURSIVENESS"

    bit_ra = bit_flags[8]
    if bit_ra == "0":
        ra = "RECURSIVENESS NOT ALLOWED"
    else:
        ra = "RECURSIVENESS ALLOWED"

    bit_flag_z = "".join(bit_flags[9:12])
    flag_z = convert_base_b_to_ten(number=bit_flag_z, base=2)

    bit_r_code = bit_flags[12:]
    dec_r_code = convert_base_b_to_ten(number=bit_r_code, base=2)
    if dec_r_code == 0:
        r_code = "NOT ERROR"
    elif dec_r_code == 1:
        r_code = "NO FORMAT ERROR IN REQUEST"
    elif dec_r_code == 2:
        r_code = "PROBLEM IN SERVER"
    elif dec_r_code == 3:
        r_code = "THE NAME NOT EXISTS"
    elif dec_r_code == 4:
        r_code = ""
    elif dec_r_code == 5:
        r_code = ""
    else:
        r_code = "RESERVATED"

    return {"DNS QR": [int(bit_q_or_r), q_or_r],
            "DNS OPERATION CODE": [bit_operation_code, operation_code, op_code],
            "DNS AA": [int(bit_aa), aa],
            "DNS TC": [int(bit_tc), tc],
            "DNS RD": [int(bit_rd), rd],
            "DNS RA": [int(bit_ra), ra],
            "DNS Z": [bit_flag_z, flag_z],
            "DNS R CODE": [bit_r_code, r_code, dec_r_code]}


def analyse_datagram_dns(datagram):
    octets_query_id = "".join(datagram[0:2])
    query_id = convert_base_b_to_ten(number=octets_query_id, base=16)

    octets_flags = "".join(datagram[2:4])
    bit_flags = convert_base_b1_to_b2(number=octets_flags, base1=16, base2=2)
    flags_result = analyse_flags_dns(octets_flags)

    octets_question_count = "".join(datagram[4:6])
    question_count = convert_base_b_to_ten(number=octets_question_count, base=16)

    octets_answer_count = "".join(datagram[6:8])
    answer_count = convert_base_b_to_ten(number=octets_answer_count, base=16)

    octets_authority_count = "".join(datagram[8:10])
    authority_count = convert_base_b_to_ten(number=octets_authority_count, base=16)

    octets_addl_record_count = "".join(datagram[10:12])
    addl_record_count = convert_base_b_to_ten(number=octets_addl_record_count, base=16)

    octets_last_part_dns = datagram[12:]

    result = {"DNS QUERY ID": [octets_query_id, query_id],
              "DNS FLAGS": [octets_flags, bit_flags],
              "DNS QUESTION COUNT": [octets_question_count, question_count],
              "DNS ANSWER COUNT": [octets_answer_count, answer_count],
              "DNS AUTHORITY COUNT": [octets_authority_count, authority_count],
              "DNS RECORD COUNT": [octets_addl_record_count, addl_record_count],
              "DNS DATA": "".join(octets_last_part_dns)}

    for key in flags_result.keys():
        result[key] = flags_result[key]

    # Gestion des requetes
    list_request_addr = []
    list_request_length_addr = []
    list_request_label_count = []
    list_request_type = []
    list_request_class = []
    for i in range(question_count):
        is_find = False
        index_octets = 0
        while not is_find:
            if octets_last_part_dns[index_octets] == "00":
                is_find = True
            else:
                index_octets += 1
        l_octets_addr = octets_last_part_dns[0:index_octets]
        octets_addr = "".join(l_octets_addr)
        list_request_length_addr.append(len(l_octets_addr))
        ascii_name = get_str_ascii(my_str=octets_addr)
        addr_name = [octets_addr, ascii_name]
        list_request_addr.append(addr_name)
        list_request_label_count.append(len(ascii_name.split(".")))
        index_octets += 1
        octets_type = "".join(octets_last_part_dns[index_octets:index_octets+2])
        dec_request_type = convert_base_b_to_ten(number=octets_type, base=16)
        if dec_request_type == 1:
            request_type = "A"
        elif dec_request_type == 2:
            request_type = "NS"
        elif dec_request_type == 3:
            request_type = "MD"
        elif dec_request_type == 4:
            request_type = "MF"
        elif dec_request_type == 5:
            request_type = "CNAME"
        elif dec_request_type == 6:
            request_type = "SOA"
        elif dec_request_type == 7:
            request_type = "MB"
        elif dec_request_type == 8:
            request_type = "MG"
        elif dec_request_type == 9:
            request_type = "MR"
        elif dec_request_type == 10:
            request_type = "NULL"
        elif dec_request_type == 11:
            request_type = "WKS"
        elif dec_request_type == 12:
            request_type = "PTR"
        elif dec_request_type == 13:
            request_type = "HINFO"
        elif dec_request_type == 14:
            request_type = "MINFO"
        elif dec_request_type == 15:
            request_type = "MX"
        elif dec_request_type == 16:
            request_type = "TXT"
        else:
            request_type = "UNKNOW"
        list_info_type = [octets_type, dec_request_type, request_type]
        list_request_type.append(list_info_type)

        octets_request_class = "".join(octets_last_part_dns[index_octets+2:index_octets+4])
        dec_request_class = convert_base_b_to_ten(number=octets_request_class, base=16)
        if dec_request_class == 1:
            request_class = "IN"
        elif dec_request_class == 2:
            request_class = "CS"
        elif dec_request_class == 3:
            request_class = "CH"
        elif dec_request_class == 4:
            request_class = "HS"
        else:
            request_class = "UKNOWN"
        list_info_request_class = [octets_request_class, dec_request_class, request_class]
        list_request_class.append(list_info_request_class)

        octets_last_part_dns = octets_last_part_dns[index_octets+4:]
    result_inter_request = {"NAME ADDRESS": list_request_addr,
                            "LENGTH": list_request_length_addr,
                            "LABEL COUNT": list_request_label_count,
                            "TYPE": list_request_type,
                            "CLASS": list_request_class}
    result["DNS REQUEST"] = result_inter_request

    if answer_count > 0:
        list_answer_addr = []
        list_answer_type = []
        list_answer_class = []
        list_answer_ttl = []
        list_answer_data_length = []
        list_answer_data = []
        for i in range(answer_count):
            octets_answer_name = "".join(octets_last_part_dns[0:2])
            if octets_answer_name == "c00c":
                answer_name = list_request_addr[i][1]
            else:
                answer_name = "unknown"
            list_answer_addr.append(answer_name)
            # answer_name
            octets_answer_type = "".join(octets_last_part_dns[2:4])
            dec_answer_type = convert_base_b_to_ten(number=octets_answer_type, base=16)
            if dec_answer_type == 1:
                answer_type = "A"
            elif dec_answer_type == 2:
                answer_type = "NS"
            elif dec_answer_type == 3:
                answer_type = "MD"
            elif dec_answer_type == 4:
                answer_type = "MF"
            elif dec_answer_type == 5:
                answer_type = "CNAME"
            elif dec_answer_type == 6:
                answer_type = "SOA"
            elif dec_answer_type == 7:
                answer_type = "MB"
            elif dec_answer_type == 8:
                answer_type = "MG"
            elif dec_answer_type == 9:
                answer_type = "MR"
            elif dec_answer_type == 10:
                answer_type = "NULL"
            elif dec_answer_type == 11:
                answer_type = "WKS"
            elif dec_answer_type == 12:
                answer_type = "PTR"
            elif dec_answer_type == 13:
                answer_type = "HINFO"
            elif dec_answer_type == 14:
                answer_type = "MINFO"
            elif dec_answer_type == 15:
                answer_type = "MX"
            elif dec_answer_type == 16:
                answer_type = "TXT"
            else:
                answer_type = "UNKNOW"
            list_info_answer_type = [octets_answer_type, dec_answer_type, answer_type]
            list_answer_type.append(list_info_answer_type)

            octets_answer_class = "".join(octets_last_part_dns[4:6])
            dec_answer_class = convert_base_b_to_ten(number=octets_answer_class, base=16)
            if dec_answer_class == 1:
                answer_class = "IN"
            elif dec_answer_class == 2:
                answer_class = "CS"
            elif dec_answer_class == 3:
                answer_class = "CH"
            elif dec_answer_class == 4:
                answer_class = "HS"
            else:
                answer_class = "UKNOWN"
            list_info_answer_class = [octets_answer_class, dec_answer_class, answer_class]
            list_answer_class.append(list_info_answer_class)

            octets_answer_ttl = "".join(octets_last_part_dns[6:10])
            dec_answer_ttl = convert_base_b_to_ten(number=octets_answer_ttl, base=16)
            answer_ttl = calcul_ttl_in_hour(ttl=dec_answer_ttl)
            list_answer_ttl.append([octets_answer_ttl, dec_answer_ttl, answer_ttl])

            octets_answer_data_length = "".join(octets_last_part_dns[10:12])
            data_answer_length = convert_base_b_to_ten(number=octets_answer_data_length, base=16)
            list_answer_data_length.append([octets_answer_data_length, data_answer_length])
            index_end = 12+data_answer_length

            octets_data_answer = octets_last_part_dns[12:index_end]
            list_answer_data.append([octets_data_answer])
            # TODO: extraire et traiter les données dans 'octets_data_answer'

            octets_last_part_dns = octets_last_part_dns[index_end:]

        result_inter_answer = {"NAME ADDRESS": list_answer_addr,
                               "TYPE": list_answer_type,
                               "CLASS": list_answer_class,
                               "TTL": list_answer_ttl,
                               "LENGTH DATA": list_answer_data_length,
                               "DATA": list_answer_data}
        result["DNS ANSWER"] = result_inter_answer

    if authority_count > 0:
        pass
        # TODO: 1 - authority count

    if addl_record_count > 0:
        list_addl_addr = []
        list_addl_type = []
        list_addl_class = []
        list_addl_ttl = []
        list_addl_data_length = []
        list_addl_data = []
        for i in range(addl_record_count):
            octets_addl_name = "".join(octets_last_part_dns[0:2])
            if octets_addl_name == "c00c":
                addl_name = list_request_addr[i][1]
            else:
                addl_name = "unknown"
            list_addl_addr.append(addl_name)
            # answer_name
            octets_addl_type = "".join(octets_last_part_dns[2:4])
            dec_addl_type = convert_base_b_to_ten(number=octets_addl_type, base=16)
            if dec_addl_type == 1:
                addl_type = "A"
            elif dec_addl_type == 2:
                addl_type = "NS"
            elif dec_addl_type == 3:
                addl_type = "MD"
            elif dec_addl_type == 4:
                addl_type = "MF"
            elif dec_addl_type == 5:
                addl_type = "CNAME"
            elif dec_addl_type == 6:
                addl_type = "SOA"
            elif dec_addl_type == 7:
                addl_type = "MB"
            elif dec_addl_type == 8:
                addl_type = "MG"
            elif dec_addl_type == 9:
                addl_type = "MR"
            elif dec_addl_type == 10:
                addl_type = "NULL"
            elif dec_addl_type == 11:
                addl_type = "WKS"
            elif dec_addl_type == 12:
                addl_type = "PTR"
            elif dec_addl_type == 13:
                addl_type = "HINFO"
            elif dec_addl_type == 14:
                addl_type = "MINFO"
            elif dec_addl_type == 15:
                addl_type = "MX"
            elif dec_addl_type == 16:
                addl_type = "TXT"
            else:
                addl_type = "UNKNOW"
            list_info_addl_type = [octets_addl_type, dec_addl_type, addl_type]
            list_addl_type.append(list_info_addl_type)

            octets_addl_class = "".join(octets_last_part_dns[4:6])
            dec_addl_class = convert_base_b_to_ten(number=octets_addl_class, base=16)
            if dec_addl_class == 1:
                addl_class = "IN"
            elif dec_addl_class == 2:
                addl_class = "CS"
            elif dec_addl_class == 3:
                addl_class = "CH"
            elif dec_addl_class == 4:
                addl_class = "HS"
            else:
                addl_class = "UKNOWN"
            list_info_addl_class = [octets_addl_class, dec_addl_class, addl_class]
            list_addl_class.append(list_info_addl_class)

            octets_addl_ttl = "".join(octets_last_part_dns[6:10])
            dec_addl_ttl = convert_base_b_to_ten(number=octets_addl_ttl, base=16)
            addl_ttl = calcul_ttl_in_hour(ttl=dec_addl_ttl)
            list_addl_ttl.append([octets_addl_ttl, dec_addl_ttl, addl_ttl])

            octets_addl_data_length = "".join(octets_last_part_dns[10:12])
            data_addl_length = convert_base_b_to_ten(number=octets_addl_data_length, base=16)
            list_addl_data_length.append([octets_addl_data_length, data_addl_length])
            index_end = 12 + data_addl_length

            octets_data_addl = octets_last_part_dns[12:index_end]
            list_addl_data.append([octets_data_addl])
            # TODO: extraire et traiter les données dans 'octets_data_answer'

            octets_last_part_dns = octets_last_part_dns[index_end:]

        result_inter_addl = {"NAME ADDRESS": list_addl_addr,
                             "TYPE": list_addl_type,
                             "CLASS": list_addl_class,
                             "TTL": list_addl_ttl,
                             "LENGTH DATA": list_addl_data_length,
                             "DATA": list_addl_data}
        result["DNS RECORD"] = result_inter_addl

    return result


def analyse_datagram_dhcp(datagram):
    # Type du message (op)
    octets_op = datagram[0]
    dec_op = convert_base_b_to_ten(number=octets_op, base=16)
    if dec_op == 1:
        op = "BootRequest"
    elif dec_op == 2:
        op = "BootReply"
    else:
        op = "Boot"

    # Type de l' adresse MAC (htype)
    octets_htype = datagram[1]
    dec_htype = convert_base_b_to_ten(number=octets_htype, base=16)
    if dec_htype == 1:
        htype = "ETHERNET"
    elif dec_htype == 6:
        htype = "IEEE 802 NETWORKS"
    elif dec_htype == 7:
        htype = "ARCNET"
    elif dec_htype == 11:
        htype = "LOCALTALK"
    elif dec_htype == 12:
        htype = "LOCALNET"
    elif dec_htype == 14:
        htype = "SMDS"
    elif dec_htype == 15:
        htype = "FRAME RELAY"
    elif dec_htype == 16:
        htype = "ASYNCHRONOUS TRANSFER MODE (ATM)"
    elif dec_htype == 17:
        htype = "HDLC"
    elif dec_htype == 18:
        htype = "FIBRE CHANNEL"
    elif dec_htype == 19:
        htype = "ASYNCHRONOUS TRANSFER MODE (ATM)"
    elif dec_htype == 20:
        htype = "SERIAL LINE"
    else:
        htype = "UNKNOWN"

    # Longueur de l'adresse MAC (htype)
    octets_hlen = datagram[2]
    dec_hlen = convert_base_b_to_ten(number=octets_hlen, base=16)

    # Compteur de saut (htops)
    octets_hops = datagram[3]
    dec_hops = convert_base_b_to_ten(number=octets_hops, base=16)

    # Identifiant de la transaction choisi aléatoirement
    octets_transaction_identifier = "".join(datagram[4:8])
    xid = convert_base_b_to_ten(number=octets_transaction_identifier, base=16)

    # Temps écoulé depuis le début de la transaction (secs)
    octets_seconds_elapsed = "".join(datagram[8:10])
    dec_seconds_elapsed = convert_base_b_to_ten(number=octets_seconds_elapsed, base=16)

    octets_flags = "".join(datagram[10:12])
    flags = convert_base_b1_to_b2(number=octets_flags, base1=16, base2=2)

    # Adresse IP du client (ciaddr)
    octets_client_ip_address_list = datagram[12:16]
    octets_client_ip_address = "".join(octets_client_ip_address_list)
    client_ip_address = get_address_ip(octets_client_ip_address_list)
    # Adresse IP du client renvoyée par le serveur DHCP (yiaddr)
    octets_your_ip_address_list = datagram[16:20]
    octets_your_ip_address = "".join(octets_your_ip_address_list)
    your_ip_address = get_address_ip(octets_your_ip_address_list)
    # Adresse IP du serveur à utiliser dans la prochaine étape du processus Bootp (siaddr)
    octets_server_ip_address_list = datagram[20:24]
    octets_server_ip_address = "".join(octets_server_ip_address_list)
    server_ip_address = get_address_ip(octets_server_ip_address_list)
    # Adresse IP de l'agent de relais DHCP (giaddr)
    octets_router_ip_address_list = datagram[24:28]
    octets_router_ip_address = "".join(octets_router_ip_address_list)
    gateway_ip_address = get_address_ip(octets_router_ip_address_list)
    # Adresse MAC du client (chaddr)
    octets_mac_address_list = datagram[28:34]
    octets_mac_address = "".join(octets_mac_address_list)
    mac_address = ":".join(octets_mac_address_list)
    octets_mac_address_padding = "".join(datagram[34:44])

    result = {"DHCP OP": [octets_op, op, dec_op],
              "DHCP HTYPE": [octets_htype, htype, dec_htype],
              "DHCP HLEN": [octets_hlen, dec_hlen],
              "DHCP HOPS": [octets_hops, dec_hops],
              "DHCP XID": [octets_transaction_identifier, xid],
              "DHCP SECS": [octets_seconds_elapsed, dec_seconds_elapsed],
              "DHCP FLAGS": [octets_flags, flags],
              "DHCP CLIENT IP ADDRESS": [octets_client_ip_address, client_ip_address],
              "DHCP YOUR IP ADDRESS": [octets_your_ip_address, your_ip_address],
              "DHCP SERVER IP ADDRESS": [octets_server_ip_address, server_ip_address],
              "DHCP GATEWAY IP ADDRESS": [octets_router_ip_address, gateway_ip_address],
              "DHCP MAC ADDRESS": [octets_mac_address, mac_address],
              "DHCP MAC ADDRESS PADDING": [octets_mac_address_padding]}

    octets_server_host_name = datagram[44:108]
    dec_server_host_name = convert_base_b_to_ten(number="".join(octets_server_host_name), base=16)
    if dec_server_host_name == 0:
        result["DHCP SNAME"] = ["00000000", "0.0.0.0", "Server host name not given"]
    else:
        result["DHCP SNAME"] = [octets_server_host_name, get_str_ascii(my_str="".join(octets_server_host_name))]
    octets_boot_file_name = datagram[108:236]
    dec_boot_file_name = convert_base_b_to_ten(number="".join(octets_boot_file_name), base=16)
    if dec_boot_file_name == 0:
        result["DHCP FILE"] = ["Boot file name not given"]
    else:
        result["DHCP FILE"] = [octets_boot_file_name, get_str_ascii(my_str="".join(octets_boot_file_name))]
    octets_magic_cookie = datagram[236:240]
    result["DHCP MAGIC COOKIE"] = [octets_magic_cookie]
    begin_option = 240

    octets_options = datagram[begin_option:]
    list_code_options = []
    list_options = []
    list_label = []
    while octets_options:
        octets_code_options = octets_options[0]
        dec_code_options = convert_base_b_to_ten(number=octets_code_options, base=16)

        if dec_code_options == 1:
            list_code_options.append(1)
            list_label.append("Subnet Mask")
            octets_length_subnet_mask = octets_options[1]
            dec_length_subnet_mask = convert_base_b_to_ten(number=octets_length_subnet_mask, base=16)
            octets_subnet_mask = ".".join([octets_options[2], octets_options[3], octets_options[4], octets_options[5]])
            subnet_mask = ".".join([str(convert_base_b_to_ten(number=octets_options[2], base=16)),
                                    str(convert_base_b_to_ten(number=octets_options[3], base=16)),
                                    str(convert_base_b_to_ten(number=octets_options[4], base=16)),
                                    str(convert_base_b_to_ten(number=octets_options[5], base=16))])
            r = [octets_length_subnet_mask, dec_length_subnet_mask, octets_subnet_mask, subnet_mask]
            list_options.append(r)
            octets_options = octets_options[dec_length_subnet_mask+2:]

        elif dec_code_options == 50:
            list_code_options.append(50)
            list_label.append("Requested IP Address")
            octets_length_ip = octets_options[1]
            dec_length_ip = convert_base_b_to_ten(number=octets_length_ip, base=16)
            octets_requested_ip_address = octets_options[2:dec_length_ip+2]
            request_ip_address = get_address_ip(a_d=octets_requested_ip_address)
            r = [octets_length_ip, dec_length_ip, "".join(octets_requested_ip_address), request_ip_address]
            list_options.append(r)
            octets_options = octets_options[dec_length_ip+2:]

        elif dec_code_options == 51:
            list_code_options.append(51)
            list_label.append("IP Address Lease Time")
            octets_options_length_lease_time = octets_options[1]
            dec_options_length_lease_time = convert_base_b_to_ten(number=octets_options_length_lease_time, base=16)
            octets_lease_time = "".join(octets_options[2:dec_options_length_lease_time+2])
            dec_options_lease_time = convert_base_b_to_ten(number=octets_lease_time, base=16)
            options_lease_time = calcul_ttl_in_hour(ttl=dec_options_lease_time)
            r = [octets_options_length_lease_time, dec_options_length_lease_time, octets_lease_time,
                 dec_options_lease_time, options_lease_time]
            list_options.append(r)
            octets_options = octets_options[dec_options_length_lease_time+2:]

        elif dec_code_options == 52:
            list_code_options.append(52)
            list_label.append("FILE/SNAME")
            octets_length_file_sname = octets_options[1]
            dec_length_file_sname = convert_base_b_to_ten(number=octets_length_file_sname, base=16)
            octets_file_sname = octets_options[2:dec_length_file_sname+2]
            dec_file_sname = convert_base_b_to_ten(number=octets_file_sname, base=16)

            if dec_file_sname == 1:
                file_sname = "Le champ 'file' est utilisé pour contenir des options"
            elif dec_file_sname == 2:
                file_sname = "Le champ 'sname' est utilisé pour contenir des options"
            elif dec_file_sname == 3:
                file_sname = "Les deux champs sont utilisés"
            else:
                file_sname = "UNKNOWM"

            r = [octets_length_file_sname, dec_length_file_sname, octets_file_sname, dec_file_sname, file_sname]
            list_options.append(r)
            octets_options = octets_options[dec_length_file_sname+2:]

        elif dec_code_options == 53:
            list_code_options.append(53)
            list_label.append("DHCP Message Type")
            octets_length_dhcp_type = octets_options[1]
            dec_length_dhcp_type = convert_base_b_to_ten(number=octets_length_dhcp_type, base=16)
            octets_dhcp_type = "".join(octets_options[2:dec_length_dhcp_type + 2])
            dec_dhcp_type = convert_base_b_to_ten(number=octets_dhcp_type, base=16)

            if dec_dhcp_type == 1:
                dhcp_type = "Discover"
            elif dec_dhcp_type == 2:
                dhcp_type = "Offer"
            elif dec_dhcp_type == 3:
                dhcp_type = "Request"
            elif dec_dhcp_type == 4:
                dhcp_type = "ACK"
            elif dec_dhcp_type == 5:
                dhcp_type = "ACK"
            elif dec_dhcp_type == 6:
                dhcp_type = "6"
            elif dec_dhcp_type == 7:
                dhcp_type = "7"
            elif dec_dhcp_type == 8:
                dhcp_type = "8"
            else:
                dhcp_type = "UNKNOWN"

            r = [octets_length_dhcp_type, dec_length_dhcp_type, octets_dhcp_type, dec_dhcp_type, dhcp_type]
            list_options.append(r)
            octets_options = octets_options[dec_length_dhcp_type+2:]

        elif dec_code_options == 54:
            list_code_options.append(54)
            list_label.append("DHCP Server Identifier")
            octets_length_ip_server_select = octets_options[1]
            dec_length_ip_server_select = convert_base_b_to_ten(number=octets_length_ip_server_select, base=16)
            octets_ip_server_select = octets_options[2:dec_length_ip_server_select+2]
            ip_server_select = get_address_ip(a_d=octets_ip_server_select)

            r = [octets_length_ip_server_select, dec_length_ip_server_select, "".join(octets_ip_server_select),
                 ip_server_select]
            list_options.append(r)
            octets_options = octets_options[dec_length_ip_server_select+2:]

        elif dec_code_options == 55:
            list_code_options.append(55)
            list_label.append("Parameter request List")
            octets_length_parameter_request_list = octets_options[1]
            dec_length_parameter_request_list = convert_base_b_to_ten(number=octets_length_parameter_request_list,
                                                                      base=16)
            if dec_length_parameter_request_list == 1:
                octets_parameter_request_list = octets_options[2]
            else:
                octets_parameter_request_list = octets_options[2:dec_length_parameter_request_list + 2]
            list_item = []
            list_item_info = []
            for elem in octets_parameter_request_list:
                item = convert_base_b_to_ten(number=elem, base=16)
                if item == 1:
                    item_info = "Subnet Mask"
                elif item == 3:
                    item_info = "Router"
                elif item == 6:
                    item_info = "Domain Name Server"
                elif item == 42:
                    item_info = "Network Time Protocol Servers"
                else:
                    item_info = "UNKNOW"
                list_item.append(item)
                list_item_info.append(item_info)

            r = [octets_length_parameter_request_list, dec_length_parameter_request_list,
                 list_item, list_item_info]
            list_options.append(r)
            octets_options = octets_options[dec_length_parameter_request_list + 2:]

        elif dec_code_options == 58:
            list_code_options.append(58)
            list_label.append("Renewal Time Value")
            octets_length_renewal_time_value = octets_options[1]
            dec_length_renewal_time_value = convert_base_b_to_ten(number=octets_length_renewal_time_value, base=16)
            octets_renewal_time_value = "".join(octets_options[2:dec_length_renewal_time_value+2])
            dec_renewal_time_value = convert_base_b_to_ten(number=octets_renewal_time_value, base=16)
            renewal_time_value = calcul_ttl_in_hour(ttl=dec_renewal_time_value)

            r = [octets_length_renewal_time_value, dec_length_renewal_time_value, octets_renewal_time_value,
                 dec_renewal_time_value, renewal_time_value]
            list_options.append(r)
            octets_options = octets_options[dec_length_renewal_time_value+2:]

        elif dec_code_options == 59:
            list_code_options.append(59)
            list_label.append("Rebinding Time Value")
            octets_length_rebinding_time_value = octets_options[1]
            dec_length_rebinding_time_value = convert_base_b_to_ten(number=octets_length_rebinding_time_value, base=16)
            octets_rebinding_time_value = "".join(octets_options[2:dec_length_rebinding_time_value + 2])
            dec_rebinding_time_value = convert_base_b_to_ten(number=octets_rebinding_time_value, base=16)
            rebinding_time_value = calcul_ttl_in_hour(ttl=dec_rebinding_time_value)

            r = [octets_length_rebinding_time_value, dec_length_rebinding_time_value, octets_rebinding_time_value,
                 dec_rebinding_time_value, rebinding_time_value]
            list_options.append(r)
            octets_options = octets_options[dec_length_rebinding_time_value + 2:]

        elif dec_code_options == 61:
            list_code_options.append(61)
            list_label.append("Client identifier")
            octets_length_client_identifier = octets_options[1]
            dec_length_client_identifier = convert_base_b_to_ten(number=octets_length_client_identifier, base=16)
            octets_client_identifier_type = octets_options[2]
            dec_client_identifier_type = convert_base_b_to_ten(number=octets_client_identifier_type, base=16)

            if dec_client_identifier_type == 1:
                client_identifier = "Ethernet"
            elif dec_client_identifier_type == 2:
                client_identifier = "2"
            elif dec_client_identifier_type == 3:
                client_identifier = "3"
            elif dec_client_identifier_type == 4:
                client_identifier = "4"
            elif dec_client_identifier_type == 5:
                client_identifier = "5"
            elif dec_client_identifier_type == 6:
                client_identifier = "6"
            elif dec_client_identifier_type == 7:
                client_identifier = "7"
            elif dec_client_identifier_type == 8:
                client_identifier = "8"
            else:
                client_identifier = "UNKNOWN"

            octets_client_mac_address = ":".join(octets_options[3:3+dec_length_client_identifier-1])

            r = [octets_length_client_identifier, dec_length_client_identifier, octets_client_identifier_type,
                 dec_client_identifier_type, client_identifier, octets_client_mac_address]
            list_options.append(r)
            octets_options = octets_options[dec_length_client_identifier + 2:]
        elif dec_code_options == 255:
            list_code_options.append(255)
            list_label.append("End")
            if len(octets_options) > 1:
                r = ["".join(octets_options[1:])]
            else:
                r = ["00"]
            list_options.append(r)
            octets_options = []
        else:
            list_code_options.append(dec_code_options)
            list_label.append(" ")
            octets_length_options_inc = octets_options[1]
            dec_length_options_inc = convert_base_b_to_ten(number=octets_length_options_inc, base=16)
            if dec_length_options_inc == 1:
                octets_options_inc = octets_options[2]
            else:
                octets_options_inc = "".join(octets_options[2:dec_length_options_inc+2])

            r = [octets_length_options_inc, dec_length_options_inc, octets_options_inc]
            list_options.append(r)
            octets_options = octets_options[dec_length_options_inc+2:]

    result["DHCP OPTIONS"] = [list_code_options, list_options, list_label]

    return result


def analyse_datagram_icmp(datagram):
    octets_type = datagram[0]
    octets_code = datagram[1]
    octets_checksum = datagram[2:4]
    octets_other = datagram[4:8]
    octets_data = datagram[8:]

    return {"ICMP": "TODO"}


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

    return {"TCP SOURCE PORT": [octets_port_source, port_source],
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
            "TCP OPTIONS": [octets_options],
            "TCP DATA": [octets_data]}


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


def analyse_packet_ipv4(packet: list) -> dict:
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
        protocole = [1, "ICMP"]
    elif dec_protocole == 6:
        protocole = [6, "TCP"]
    elif dec_protocole == 17:
        protocole = [17, "UDP"]
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

    if dec_protocole == 1:
        protocole = "ICMP"
        higher_level = analyse_datagram_icmp(datagram=packet[20:])
    elif dec_protocole == 6:
        protocole = "TCP"
        higher_level = analyse_segment_tcp(segment=packet[20:])
    elif dec_protocole == 17:
        protocole = "UDP"
        # TODO: rédéfinir la fonction analyse_segment_udp en passant le pseudo entete en argument à la fonction
        higher_level = analyse_segment_udp(segment=packet[20:])
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
                    "IP ADDRESS IP DESTINATION": [octets_ip_d, address_ip_destination]}

    for info in higher_level.keys():
        final_result[info] = higher_level[info]

    return final_result


def analyse_packet_ipv6(packet: list):
    return {"IPV6": "TODO"}


def analyse_packet_arp(packet: list):
    return {"ARP": "TODO"}


def analyse_packet_rarp(packet: list):
    return {"RARP": "TODO"}


def analyse_packet_ibm(packet: list):
    return {"IBM": "TODO"}


def analyse_frame_ethernet2(frame: list) -> dict:
    """
    Fonction qui me permet d' analyser une trame Ethernet2

    :param frame: list contenant les octets à analyser
    :return: return un dictionnaire contenant les informations de la trame
    """

    # Trame Ethernet: Adresse destination + Adresse source + Protocole de couche + Champs de données + FCS
    bloc_ethernet_begin = frame[0:14]
    # bloc_ethernet_end = frame[-4:]
    # fcs = "".join(bloc_ethernet_end)
    octets_address_mac_destination = "".join(bloc_ethernet_begin[0:6])
    address_mac_destination = ":".join(bloc_ethernet_begin[0:6])
    octets_address_mac_source = "".join(bloc_ethernet_begin[6:12])
    address_mac_source = ":".join(bloc_ethernet_begin[6:12])

    protocole_ethernet = "".join(bloc_ethernet_begin[12:14])
    protocole_ethernet = protocole_ethernet.upper()
    # packet = frame[14:len(frame)-4]
    packet = frame[14:]
    if protocole_ethernet == "0800":
        protocole = "IPv4"
        result_analyse_packet = analyse_packet_ipv4(packet=packet)
    elif protocole_ethernet == "86DD":
        protocole = "IPv6"
        result_analyse_packet = analyse_packet_ipv6(packet=packet)
    elif protocole_ethernet == "0806":
        protocole = "ARP"
        result_analyse_packet = analyse_packet_arp(packet=packet)
    elif protocole_ethernet == "8035":
        protocole = "RARP"
        result_analyse_packet = analyse_packet_rarp(packet=packet)
    elif protocole_ethernet == "80D5":
        protocole = "IBM SNA Service on Ether"
        result_analyse_packet = analyse_packet_ibm(packet=packet)
    else:
        protocole = "UNKNOWN"
        result_analyse_packet = "BAD PACKET"

    final_result = {"ETHERNET ADDRESS MAC DESTINATION": [octets_address_mac_destination, address_mac_destination],
                    "ETHERNET ADDRESS MAC SOURCE ETHERNET": [octets_address_mac_source, address_mac_source],
                    "ETHERNET PROTOCOLE": [protocole_ethernet, protocole]}
    # "ETHERNET FCS": [fcs]}

    for info in result_analyse_packet.keys():
        final_result[info] = result_analyse_packet[info]

    return final_result


def get_info_trame(frame: list) -> str:
    info_frame = analyse_frame_ethernet2(frame=frame)
    final_print = "Informations trame Ethernet:\n"
    final_print += f"\t-[Eth2] Adresse mac destination: 0x{info_frame['ETHERNET ADDRESS MAC DESTINATION'][0]}"\
                   f" ({info_frame['ETHERNET ADDRESS MAC DESTINATION'][1]})\n"
    final_print += f"\t-[Eth2] Adresse mac source: 0x{info_frame['ETHERNET ADDRESS MAC SOURCE ETHERNET'][0]}" \
                   f" ({info_frame['ETHERNET ADDRESS MAC SOURCE ETHERNET'][1]})\n"
    final_print += f"\t-[Eth2] Protocole ethernet: 0x{info_frame['ETHERNET PROTOCOLE'][0]}" \
                   f" ({info_frame['ETHERNET PROTOCOLE'][1]})\n"
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
            final_print += f"\t-[TCP] Données: 0x{info_frame['TCP DATA'][0]}"

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
        pass
    elif info_frame['ETHERNET PROTOCOLE'][0] == "0835":
        pass
    elif info_frame['ETHERNET PROTOCOLE'][0] == "80D5":
        pass
    else:
        final_print += f"\t- UNKNOWN PROTOCOLE\n"

    return final_print
