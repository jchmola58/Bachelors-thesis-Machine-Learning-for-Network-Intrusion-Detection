import os
import pandas as pd

# cesta k všetkým log
logs_parent_folder = "C:/Users/jchmo/pcap/pcap"

# prázdny zoznam
all_conn_logs = []

# prejdi všetky priečinky
for folder_name in os.listdir(logs_parent_folder):
    folder_path = os.path.join(logs_parent_folder, folder_name)
    
    if os.path.isdir(folder_path) and folder_name.endswith("_logs"):
        conn_log_path = os.path.join(folder_path, "conn.log")
        
        if os.path.exists(conn_log_path):
            try:
                df = pd.read_csv(
                    conn_log_path,
                    sep="\t",
                    comment="#",
                    header=None
                )
                
                # priradenie názvov stĺpcov
                df.columns = [
                    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                    "proto", "service", "duration", "orig_bytes", "resp_bytes",
                    "conn_state", "local_orig", "local_resp", "missed_bytes",
                    "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
                    "tunnel_parents", "community_id"
                ]
                
                # meno súboru, z kade je
                df['source_pcap'] = folder_name.replace('_logs', '')
                
                all_conn_logs.append(df)
                
                print(f" Načítané: {conn_log_path}")
            except Exception as e:
                print(f"Chyba pri načítaní {conn_log_path}: {e}")

# spoj logy do jedného
if all_conn_logs:
    merged_conn_df = pd.concat(all_conn_logs, ignore_index=True)
    print("\n Spojený DataFrame veľkosť:", merged_conn_df.shape)

    # analýza
    print("\n Rozdelenie podľa protokolov:")
    print(merged_conn_df['proto'].value_counts())

else:
    print("Nenašli sa žiadne conn.log súbory.")