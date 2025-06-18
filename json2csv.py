import json
import pandas as pd
import os
import sys

def swap_special_chars_to_underscore(input_string):
    result = '' # to store the output
    
    # Check if the character is alphanumeric
    # If alphanumeric, add the character to the result string
    # If not alphanumeric, add an underscore to the result string
    for char in input_string:
        if char.isalnum():
            result += char
        else:
            result += '_'
    
    return result

def progressBar(count_value, total, slow_print, suffix=''):
    """
    A simple and tidy progress bar to track status
    """
    # Adapted from: https://www.geeksforgeeks.org/progress-bars-in-python/

    bar_length = 25
    filled_up_Length = int(round(bar_length* count_value / float(total)))
    percentage = round(100.0 * count_value/float(total),1)
    bar = '=' * filled_up_Length + ' ' * (bar_length - filled_up_Length)
    
    # This new way of printing improves when using parallelization
    # if on slow mode and file is large, update for each 1k packets
    # if on slow mode and file is medium sized, update for each 100 packets
    # else if on slow mode and file is small, update for each 10 packets
    # else if not on slow mode, update at every packet (the original way)
    # else don't do anything (i.e. skip)
    if (slow_print and total >= 10000 and count_value % 1000 == 0):
        sys.stdout.write('[%s] %s%s: %s\n' %(bar, percentage, '%', suffix))
    elif (slow_print and total > 1000 and total < 10000 and count_value % 100 == 0):
        sys.stdout.write('[%s] %s%s: %s\n' %(bar, percentage, '%', suffix))
    elif (slow_print and total <= 1000 and count_value % 10 == 0):
        sys.stdout.write('[%s] %s%s: %s\n' %(bar, percentage, '%', suffix))
    elif (not slow_print):
        sys.stdout.write('[%s] %s%s: %s\r' %(bar, percentage, '%', suffix))

def parse(input_file_path, output_folder, print_control=False):
    """
    A function to parse JSON PCAP-style files to a CSV format
    """

    # check if path is empty then ask user to provide it
    if (not input_file_path):
        print("[ERRO] The file path was not provided!")
        print("[INFO] Please, provide the file path below")
        input_file_path = input("> ")

    file_path_without_format = os.path.splitext(input_file_path)[0] # remove '.json' from old file name
    file_name_without_format = file_path_without_format.split("/")
    file_name_without_format = file_name_without_format[len(file_name_without_format)-1] # get the clean file name only
    new_file_name = file_name_without_format + '.csv'
    new_file_with_path = output_folder + new_file_name

    JSON_data=open(input_file_path).read()
    print(f"[INFO] JSON file {file_name_without_format} opened successfully")
    JSONArray = json.loads(JSON_data)
    print("[INFO] JSON data imported successfully")
        
    length = len(JSONArray)
    print("[DEBU]", length, "data frames to be converted from", file_name_without_format) # DEBUG

    labels = ['Packet_no','Timestamp','Time_delta','Source_IP','Destination_IP','Frame_type','Frame_total_length','Frame_header_length',
            'Frame_payload_length','Source_port','Destination_port','TCP_completeness','TCP_compl_reset','TCP_compl_fin','TCP_compl_data',
            'TCP_compl_ack','TCP_compl_syn_ack','TCP_compl_syn','TCP_compl_str','TCP_flags_bin','TCP_flags_str','TCP_window_size',
            'TCP_window_size_scale','Frame_protocols','IP_protocols','IP_flag_reserved_bit','IP_flag_dont_fragment','IP_flag_more_fragments',
            'TTL', 'TCP_header_length','Data_length','QUIC_packet_length','QUIC_length']

    df = pd.DataFrame(columns = labels)
    df.to_csv(new_file_with_path, header = True, index = False)
    for obj in range(length):

        try:
            pkt_number = JSONArray[obj]['_source']['layers']['frame']['frame.number']
        except Exception:
            timestamp = None

        try:
            timestamp = JSONArray[obj]['_source']['layers']['frame']['frame.time_relative']
        except Exception:
            timestamp = None

        try:
            time_since_last_pkt = JSONArray[obj]['_source']['layers']['frame']['frame.time_delta']
        except Exception:
            time_since_last_pkt = None

        try:
             ipv4_ip_src = JSONArray[obj]['_source']['layers']['ip']['ip.src']
        except Exception:
            ipv4_ip_src = None

        try:
            ipv4_ip_dst = JSONArray[obj]['_source']['layers']['ip']['ip.dst']
        except Exception:
            ipv4_ip_dst = None

        try:
            frame_type = JSONArray[obj]['_source']['layers']['frame']['frame.encap_type']
        except Exception:
            frame_type = None
            # more info on that: https://gitlab.com/wireshark/wireshark/-/blob/master/wiretap/wtap.h#L87

        try:
            frame_len = JSONArray[obj]['_source']['layers']['frame']['frame.len']
        except Exception:
            frame_len = None

        try:
            header_len = JSONArray[obj]['_source']['layers']['ip']['ip.hdr_len']
        except Exception:
            header_len = None

        try:
            payload_len = JSONArray[obj]['_source']['layers']['udp']['udp.length']
        except Exception:
            try:
                payload_len = JSONArray[obj]['_source']['layers']['tcp']['tcp.len']
            except Exception:
                payload_len = None

        try:
            src_port = JSONArray[obj]['_source']['layers']['udp']['udp.srcport']
        except Exception:
            try:
                src_port = JSONArray[obj]['_source']['layers']['tcp']['tcp.srcport']
            except Exception:
                src_port = None
        
        try:
            dst_port = JSONArray[obj]['_source']['layers']['udp']['udp.dstport']
        except Exception:
            try:
                dst_port = JSONArray[obj]['_source']['layers']['tcp']['tcp.dstport']
            except Exception:
                dst_port = None
        
        # TCP only begin #
        try:
            tcp_completeness = JSONArray[obj]['_source']['layers']['tcp']['tcp.completeness']
        except Exception:
            tcp_completeness = None
        
        # TODO forcibly convert these "completeness flags" to int or bool
        try:
            tcp_completeness_reset = JSONArray[obj]['_source']['layers']['tcp']['tcp.completeness_tree']['tcp.completeness.rst']
        except Exception:
            tcp_completeness_reset = None

        try:
            tcp_completeness_fin = JSONArray[obj]['_source']['layers']['tcp']['tcp.completeness_tree']['tcp.completeness.fin']
        except Exception:
            tcp_completeness_fin = None

        try:
            tcp_completeness_data = JSONArray[obj]['_source']['layers']['tcp']['tcp.completeness_tree']['tcp.completeness.data']
        except Exception:
            tcp_completeness_data = None

        try:
            tcp_completeness_ack = JSONArray[obj]['_source']['layers']['tcp']['tcp.completeness_tree']['tcp.completeness.ack']
        except Exception:
            tcp_completeness_ack = None

        try:
            tcp_completeness_syn_ack = JSONArray[obj]['_source']['layers']['tcp']['tcp.completeness_tree']['tcp.completeness.syn-ack']
        except Exception:
            tcp_completeness_syn_ack = None

        try:
            tcp_completeness_syn = JSONArray[obj]['_source']['layers']['tcp']['tcp.completeness_tree']['tcp.completeness.syn']
        except Exception:
            tcp_completeness_syn = None

        try:
            tcp_completeness_str = JSONArray[obj]['_source']['layers']['tcp']['tcp.completeness_tree']['tcp.completeness.str']
            # if (tcp_completeness_str == "[ Null ]"): # TODO check if this won't break anything
            #     tcp_completeness_str = None
            tcp_completeness_str = ''.join(filter(str.isalnum, tcp_completeness_str))
        except Exception:
            tcp_completeness_str = None

        try:
            tcp_flags_hex = JSONArray[obj]['_source']['layers']['tcp']['tcp.flags']
            # if needed, adjust 010b and 10 to the desired length below
            # see alternatives here: https://www.geeksforgeeks.org/python-ways-to-convert-hex-into-binary/
            tcp_flags_bin = "{0:010b}".format(int(str(tcp_flags_hex), 10))
        except Exception:
            tcp_flags_bin = None
        
        try:
            tcp_flags_str = JSONArray[obj]['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.str']
            tcp_flags_str = ''.join(filter(str.isalnum, tcp_flags_str))
        except Exception:
            tcp_flags_str = None

        try:
            tcp_window_size = JSONArray[obj]['_source']['layers']['tcp']['tcp.window_size']
        except Exception:
            tcp_window_size = None

        try:
            tcp_window_size_scalefactor = JSONArray[obj]['_source']['layers']['tcp']['tcp.window_size_scalefactor']
        except Exception:
            tcp_window_size_scalefactor = None
        # TCP only end #

        try:
            frame_protocols = JSONArray[obj]['_source']['layers']['frame']['frame.protocols']
            frame_protocols = ''.join(filter(str.isalnum, frame_protocols))
            # filter just erases all special chars, to keep the strings human readable, it's better to swap the chars instead
            # frame_protocols = swap_special_chars_to_underscore(frame_protocols) # TODO test the performance of using this function
        except Exception:
            frame_protocols = None

        try:
            ip_protocols = JSONArray[obj]['_source']['layers']['ip']['ip.proto']
        except Exception:
            ip_protocols = None

        try:
            ip_flag_reserved_bit = JSONArray[obj]['_source']['layers']['ip']['ip.flags_tree']['ip.flags.rb']
        except Exception:
            ip_flag_reserved_bit = None

        try:
            ip_flag_dont_fragment = JSONArray[obj]['_source']['layers']['ip']['ip.flags_tree']['ip.flags.df']
        except Exception:
            ip_flag_dont_fragment = None

        try:
            ip_flag_more_fragments = JSONArray[obj]['_source']['layers']['ip']['ip.flags_tree']['ip.flags.mf']
        except Exception:
            ip_flag_more_fragments = None
        
        try:
            ip_ttl = JSONArray[obj]['_source']['layers']['ip']['ip.ttl']
        except Exception:
            ip_ttl = None

        # TCP only begin #
        try:
            tcp_header_length = JSONArray[obj]['_source']['layers']['tcp']['tcp.hdr_len']
        except Exception:
            tcp_header_length = None
        # TCP only end #

        # UDP only begin #
        try:
            data_length = JSONArray[obj]['_source']['layers']['data']['data.len']
        except Exception:
            data_length = None
        # UDP only end #

        # QUIC only begin #
        try:
            quic_packet_length = JSONArray[obj]['_source']['layers']['quic']['quic.packet_length']
        except Exception:
            quic_packet_length = None
        
        try:
            quic_length = JSONArray[obj]['_source']['layers']['quic']['quic.length']
        except Exception:
            quic_length = None
        # QUIC only end #

        record = [(pkt_number, timestamp, time_since_last_pkt, ipv4_ip_src, ipv4_ip_dst, frame_type, frame_len, 
                header_len, payload_len, src_port, dst_port, tcp_completeness, tcp_completeness_reset, 
                tcp_completeness_fin, tcp_completeness_data, tcp_completeness_ack, tcp_completeness_syn_ack, 
                tcp_completeness_syn, tcp_completeness_str, tcp_flags_bin, tcp_flags_str, tcp_window_size, 
                tcp_window_size_scalefactor, frame_protocols, ip_protocols, ip_flag_reserved_bit, 
                ip_flag_dont_fragment, ip_flag_more_fragments, ip_ttl, tcp_header_length, data_length, 
                quic_packet_length, quic_length)]

        df = pd.DataFrame.from_records(record, columns=labels)
        with open(new_file_with_path, 'a', encoding='utf-8') as f:
            # old way of reporting status, commented to avoiding flooding the stdout
            # print("[INFO] Writing dataframe", obj, "of", length, "(", round(obj*100/length, 1) ,"% ) to CSV") 
            progressBar(obj, length, print_control, f"Writing {new_file_name}")
            df.to_csv(f, header=False, index = False)
            
    print("\n[INFO] All", length, "records from", new_file_name, "were successfully written")
    # print("[DEBU] Columns of CSV are", list(df)) # DEBUG

# parse("", "./") # Enable this line to run in "stand alone" mode (e.g. not importing as python module)
