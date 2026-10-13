import pandas as pd
import glob
import os

# cesta, kde sú súbory
folder_path = r"C:\Users\jchmo\pcap\pcap\prejdene_logy_cicflowmetrom"

# features
selected_features = [
    'Pkt Size Avg', 'Pkt Len Max', 'Bwd Seg Size Avg', 'Bwd Pkt Len Max', 'Pkt Len Mean',
    'Bwd Pkt Len Std', 'Pkt Len Var', 'Fwd Seg Size Avg', 'Bwd Pkt Len Mean', 'Pkt Len Std',
    'Subflow Fwd Byts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts'
]

all_flows = []

all_files = glob.glob(os.path.join(folder_path, "*_Flow.csv"))
print(f"Nájdených CSV súborov: {len(all_files)}")

for filename in all_files:
    try:
        file_size = os.path.getsize(filename)
        if file_size > 300 * 1024 * 1024:
            print(f"Súbor {filename} je príliš veľký, preskakujem.")
            continue

        print(f"🔄 Spracovávam: {filename}")

        df = pd.read_csv(filename)

        # doplnenie chýbajúcich stĺpcov nulami
        missing_cols = [col for col in selected_features if col not in df.columns]
        for col in missing_cols:
            df[col] = 0.0

        df_final = df[selected_features]

        all_flows.append(df_final)

    except Exception as e:
        print(f"Chyba pri spracovaní {filename}: {e}")

# spojenie všetkých flowov
if all_flows:
    final_dataset = pd.concat(all_flows, ignore_index=True)
    output_csv = os.path.join(folder_path, "combined_features_only.csv")
    final_dataset.to_csv(output_csv, index=False)
    print(f"Uložené featury do: {output_csv}")
else:
    print("Žiadne featury neboli vygenerované.")