import os
import pandas as pd

# cesta k priečinkom
logs_parent_folder = "C:/Users/jchmo/pcap/pcap"

# prázdny zoznam
all_weird_logs = []

# Prejdi všetky priečinky
for folder_name in os.listdir(logs_parent_folder):
    folder_path = os.path.join(logs_parent_folder, folder_name)
    
    if os.path.isdir(folder_path) and folder_name.endswith("_logs"):
        weird_log_path = os.path.join(folder_path, "weird.log")
        
        if os.path.exists(weird_log_path):
            try:
                df = pd.read_csv(
                    weird_log_path,
                    sep="\t",
                    comment="#",
                    header=None
                )
                
                # priradenie správnych názvov stĺpcov
                df.columns = [
                    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                    "name", "addl", "notice", "peer", "community_id"
                ]
                
                # meno zdrojového pcap
                df['source_pcap'] = folder_name.replace('_logs', '')
                
                all_weird_logs.append(df)
                
                print(f"Načítané: {weird_log_path}")
            except Exception as e:
                print(f"Chyba pri načítaní {weird_log_path}: {e}")

# spoj všetko
if all_weird_logs:
    merged_weird_df = pd.concat(all_weird_logs, ignore_index=True)
    print("\n Spojený DataFrame veľkosť:", merged_weird_df.shape)

    # analýza
    print("\n Počet podozrivých udalostí podľa typu:")
    print(merged_weird_df['name'].value_counts())

    # uloženie do csv
    merged_weird_df.to_csv("C:/Users/jchmo/pcap/merged_weird_logs.csv", index=False)
    print("\n Uložený výsledný merged_weird_logs.csv!")
else:
    print("Nenašli sa žiadne weird.log súbory.")


import matplotlib.pyplot as plt

# graf a analýza
anomaly_counts = merged_weird_df['name'].value_counts()

plt.figure(figsize=(12, 6))
anomaly_counts.head(10).plot(kind='bar')
plt.title('Top 10 najčastejších anomálií v weird.log')
plt.xlabel('Typ anomálie')
plt.ylabel('Počet výskytov')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.show()