import pandas as pd
import matplotlib.pyplot as plt

# cesta k súboru
predictions_path = r"C:\Users\jchmo\pcap\pcap\prejdene_logy_cicflowmetrom\ensemble_predictions_final.csv"

# načítanie predikcií
df = pd.read_csv(predictions_path)

# kontrola riadkov
print(df.head())

# výpočet počtu tried
counts = df['prediction'].value_counts()
print("\nPočet predikcií:")
print(counts)

# vypísaŤ
print("\nŠtatistika predikcií:")
print(f"BENIGN (0): {counts.get(0, 0)} flowov")
print(f"ÚTOK (1): {counts.get(1, 0)} flowov")

# graf
labels = ['Benign', 'Útok']
sizes = [counts.get(0, 0), counts.get(1, 0)]

plt.figure(figsize=(6,6))
plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
plt.title('Rozdelenie predikcií Ensemble modelu')
plt.axis('equal')
plt.show()

# vyhodnotenie
plt.figure(figsize=(10,6))
plt.hist(df['ensemble_probability'], bins=50, color='blue', edgecolor='black')
plt.title('Histogram pravdepodobností ensemble modelu')
plt.xlabel('Pravdepodobnosť')
plt.ylabel('Počet flowov')
plt.grid(True)
plt.show()

print(df[['ensemble_probability']].describe())