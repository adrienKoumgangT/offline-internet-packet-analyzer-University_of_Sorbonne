from utils.utils import *


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
