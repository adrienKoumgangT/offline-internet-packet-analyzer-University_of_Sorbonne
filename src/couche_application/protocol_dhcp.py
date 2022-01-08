from utils.utils import *


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
