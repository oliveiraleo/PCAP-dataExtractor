import json
import pandas as pd
import os

def parse(input_file_path, output_folder):
    """
    A function to parse JSON PCAP-style files to a CSV format
    """

    # check if path is empty then ask user to provide it
    if (not input_file_path):
        print("[ERRO] The file path was not provided!")
        print("[INFO] Please, provide the file path below")
        input_file_path = input("> ")

    JSON_data=open(input_file_path).read()
    print("JSON file loaded !!")
    JSONArray = json.loads(JSON_data)
    print("JSON file loaded !!")
        
    length = len(JSONArray)

    labels = ['Packet_no', 'Timestamp', 'Source_IP','Destination_IP','Frame_type','Frame_total_length','Frame_header_length', 'Frame_payload_length',
            'Frame_protocols', 'IP_protocols', 'IP_flag_reserved_bit', 'IP_flag_dont_fragment', 'IP_flag_more_fragments', 'TTL', 'Data_length']

    file_path_without_format = os.path.splitext(input_file_path)[0] # remove '.json' from old file name
    new_file_name = output_folder + file_path_without_format + '.csv'

    df = pd.DataFrame(columns = labels)
    df.to_csv(new_file_name, header = True, index = False)
    for obj in range(length):

        try:
            pkt_number = JSONArray[obj]['_source']['layers']['frame']['frame.number']
        except Exception:
            timestamp = "-"

        try:
            timestamp = JSONArray[obj]['_source']['layers']['frame']['frame.time_relative']
        except Exception:
            timestamp = "-"

        try:
             ipv4_ip_src = JSONArray[obj]['_source']['layers']['ip']['ip.src']
        except Exception:
            ipv4_ip_src = "-"

        try:
            ipv4_ip_dst = JSONArray[obj]['_source']['layers']['ip']['ip.dst']
        except Exception:
            ipv4_ip_dst = "-"

        try:
            frame_type = JSONArray[obj]['_source']['layers']['frame']['frame.encap_type']
        except Exception:
            frame_type = "-"
            # more info on that: https://gitlab.com/wireshark/wireshark/-/blame/master/wiretap/wtap.h#L87

        try:
            frame_len = JSONArray[obj]['_source']['layers']['frame']['frame.len']
        except Exception:
            frame_len = "-"

        try:
            header_len = JSONArray[obj]['_source']['layers']['ip']['ip.hdr_len']
        except Exception:
            header_len = "-"

        try:
            payload_len = JSONArray[obj]['_source']['layers']['udp']['udp.length']
            # TODO get other payload lenghts from other protocols too
        except Exception:
            payload_len = "-"

        try:
            frame_protocols = JSONArray[obj]['_source']['layers']['frame']['frame.protocols']
        except Exception:
            frame_protocols = "-"

        try:
            ip_protocols = JSONArray[obj]['_source']['layers']['ip']['ip.proto']
        except Exception:
            ip_protocols = "-"

        try:
            ip_flag_reserved_bit = JSONArray[obj]['_source']['layers']['ip']['ip.flags_tree']['ip.flags.rb']
        except Exception:
            ip_flag_reserved_bit = "-"

        try:
            ip_flag_dont_fragment = JSONArray[obj]['_source']['layers']['ip']['ip.flags_tree']['ip.flags.df']
        except Exception:
            ip_flag_dont_fragment = "-"

        try:
            ip_flag_more_fragments = JSONArray[obj]['_source']['layers']['ip']['ip.flags_tree']['ip.flags.mf']
        except Exception:
            ip_flag_more_fragments = "-"
        
        try:
            ip_ttl = JSONArray[obj]['_source']['layers']['ip']['ip.ttl']
        except Exception:
            ip_ttl = "-"

        try:
            data_length = JSONArray[obj]['_source']['layers']['data']['data.len']
        except Exception:
            data_length = "-"

        record = [(pkt_number, timestamp, ipv4_ip_src, ipv4_ip_dst, frame_type, frame_len, header_len, payload_len, 
                frame_protocols, ip_protocols, ip_flag_reserved_bit, ip_flag_dont_fragment, ip_flag_more_fragments,
                 ip_ttl, data_length)]

        df = pd.DataFrame.from_records(record, columns=labels)
        with open(new_file_name, 'a', encoding='utf-8') as f:
            print("Writing dataframe ", obj, " to CSV")
            df.to_csv(f, header=False, index = False)
            
    print("All", len(JSONArray), "records written successsfully !! :)")
    print("Columns of CSV are", list(df))

parse("", "./")