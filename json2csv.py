import json
import os
import csv
import pandas as pd
import csv

JSON_data=open('data.json').read()
print("JSON file loaded !!")
JSONArray = json.loads(JSON_data)
print("JSON file loaded !!")
    
length = len(JSONArray)

labels = ['Timestamp', 'Source_IP','Destination_IP','ICMPv6_Code','Version','Rank']

df = pd.DataFrame(columns = labels)
df.to_csv('json_parsed.csv', header = True, index = False)
for obj in range(length):

    try:
        timestamp = JSONArray[obj]['_source']['layers']['frame']['frame.time']
    except Exception:
        timestamp = "-"
        
    try:
        ipv6_src_host = JSONArray[obj]['_source']['layers']['ipv6']['ipv6.src_host']
    except Exception:
        ipv6_src_host = "-"

    try:
        ipv6_dst_host = JSONArray[obj]['_source']['layers']['ipv6']['ipv6.dst_host']
    except Exception:
        ipv6_dst_host = "-"

    try:
        icmpv6_code = JSONArray[obj]['_source']['layers']['icmpv6']['icmpv6.code']
    except Exception:
        icmpv6_code = "-"

    try:
        icmpv6_rpl_dio_version = JSONArray[obj]['_source']['layers']['icmpv6']['icmpv6.rpl.dio.version']
    except Exception:
        icmpv6_rpl_dio_version = "-"

    try:
        icmpv6_rpl_dio_rank = JSONArray[obj]['_source']['layers']['icmpv6']['icmpv6.rpl.dio.rank']
    except Exception:
        icmpv6_rpl_dio_rank = "-"

    record = [(timestamp, ipv6_src_host, ipv6_dst_host, icmpv6_code, icmpv6_rpl_dio_version, icmpv6_rpl_dio_rank)]
    
    df = pd.DataFrame.from_records(record, columns=labels)
    with open('json_parsed.csv', 'a', encoding='utf-8') as f:
        print("Writing dataframe ", obj, " to CSV")
        df.to_csv(f, header=False, index = False)
        
print("All", len(JSONArray), "records written successsfully !! :)")
print("Columns of CSV are", list(df))


