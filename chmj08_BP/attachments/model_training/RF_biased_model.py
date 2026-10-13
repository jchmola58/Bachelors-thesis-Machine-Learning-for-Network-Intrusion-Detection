import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# Definované features
selected_features = [
    'Average Packet Size', 'Max Packet Length', 'Avg Bwd Segment Size',
    'Bwd Packet Length Max', 'Packet Length Mean',
    'Bwd Packet Length Std', 'Packet Length Variance',
    'Avg Fwd Segment Size', 'Bwd Packet Length Mean', 'Packet Length Std',
    'Subflow Fwd Bytes', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets'
]

# Načítanie datasetov
file_paths = [
    "archive/Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "archive/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "archive/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "archive/Wednesday-workingHours.pcap_ISCX.csv",
    "archive/Tuesday-WorkingHours.pcap_ISCX.csv",
    "archive/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "archive/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
]

dataframes = []
for file in file_paths:
    df = pd.read_csv(file)
    df.columns = df.columns.str.strip()  
    df['Label'] = df['Label'].apply(lambda x: 0 if "BENIGN" in x.upper() else 1)  
    dataframes.append(df)

# spojenie dát
df = pd.concat(dataframes, ignore_index=True)


# odstránenie nekorektných hodnô
X = df[selected_features].replace([np.inf, -np.inf], np.nan).dropna()
y = df['Label'].loc[X.index]

'''
# normalizácia dát
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
'''

# train test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)


# model
rf_model = RandomForestClassifier(
    class_weight="balanced",
    max_depth=20,
    max_features='log2',
    min_samples_leaf=1,
    min_samples_split=5,
    n_estimators=100,
    oob_score=True,
    random_state=42
)
rf_model.fit(X_train, y_train)

# predikcia
y_pred = rf_model.predict(X_test)

# vyhodnotenie
accuracy = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred)
conf_matrix = confusion_matrix(y_test, y_pred)

# výpis výsledkov
print(f"Accuracy: {accuracy:.4f}")
print("Classification Report:\n", report)
print("Confusion Matrix:\n", conf_matrix)

# confusion Matrix
plt.figure(figsize=(6, 5))
sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues', xticklabels=['Benign', 'Attack'], yticklabels=['Benign', 'Attack'])
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')
plt.show()


joblib.dump(rf_model, 'RF_idk.pkl')
