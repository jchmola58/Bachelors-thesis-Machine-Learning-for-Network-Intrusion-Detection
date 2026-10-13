import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from imblearn.over_sampling import SMOTE

# definované features
selected_features = [
    'Average Packet Size', 'Max Packet Length', 'Avg Bwd Segment Size',
    'Bwd Packet Length Max', 'Packet Length Mean',
    'Bwd Packet Length Std', 'Packet Length Variance',
    'Avg Fwd Segment Size', 'Bwd Packet Length Mean', 'Packet Length Std',
    'Subflow Fwd Bytes', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets'
]

# definované features v CICIDS2018 / mapping
selected_features_CIC2018 = [
    'Pkt Size Avg', 'Pkt Len Max', 'Bwd Seg Size Avg',
    'Bwd Pkt Len Max', 'Pkt Len Mean', 'Bwd Pkt Len Std',
    'Pkt Len Var', 'Fwd Seg Size Avg', 'Bwd Pkt Len Mean',
    'Pkt Len Std', 'Subflow Fwd Byts', 'Fwd Pkt Len Max',
    'Fwd Pkt Len Min', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts'
]

# Cesty k súborom
train_files = [
    "archive/Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "archive/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "archive/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "archive/Wednesday-workingHours.pcap_ISCX.csv",
    "archive/Tuesday-WorkingHours.pcap_ISCX.csv",
    "archive/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "archive/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
]

test_files = [
    "CSE-CIC-IDS2018\CSE-CIC-IDS2018\SSH-Bruteforce.csv",
    "CSE-CIC-IDS2018\CSE-CIC-IDS2018\DDoS attacks-LOIC-HTTP.csv",
    "CSE-CIC-IDS2018\CSE-CIC-IDS2018\DoS attacks-Hulk.csv",
    "CSE-CIC-IDS2018\CSE-CIC-IDS2018\FTP-BruteForce.csv",
    "CSE-CIC-IDS2018\CSE-CIC-IDS2018\Infilteration.csv",
    "CSE-CIC-IDS2018\CSE-CIC-IDS2018\DDOS attack-HOIC.csv",
    "CSE-CIC-IDS2018\CSE-CIC-IDS2018\Bot.csv",
    "CSE-CIC-IDS2018\CSE-CIC-IDS2018\DoS attacks-SlowHTTPTest.csv",
    "CSE-CIC-IDS2018\CSE-CIC-IDS2018\DoS attacks-GoldenEye.csv",
    "CSE-CIC-IDS2018\CSE-CIC-IDS2018\Brute Force -Web.csv",
    "CSE-CIC-IDS2018\CSE-CIC-IDS2018\Brute Force -XSS.csv",
    "CSE-CIC-IDS2018\CSE-CIC-IDS2018\DDOS attack-LOIC-UDP.csv",
    "CSE-CIC-IDS2018\CSE-CIC-IDS2018\DoS attacks-Slowloris.csv",
    "CSE-CIC-IDS2018\CSE-CIC-IDS2018\SQL Injection.csv"
]

# funkcia na načítanie a spracovanie dát
def load_and_process(files):
    dfs = []
    for file in files:
        df = pd.read_csv(file)
        df.columns = df.columns.str.strip()

        if df['Label'].dtype == object:
            df['Label'] = df['Label'].apply(lambda x: 0 if isinstance(x, str) and "BENIGN" in x.upper() else 1)
        else:
            df['Label'] = df['Label'].apply(lambda x: 0 if x == 0 else 1)

        dfs.append(df)
    df_all = pd.concat(dfs, ignore_index=True)
    X = df_all[selected_features].replace([np.inf, -np.inf], np.nan).dropna()
    y = df_all['Label'].loc[X.index]
    return X, y


# funkcia na načítanie a spracovanie dát CIC-IDS2018
def load_and_processCIC2018(files):
    dfs = []
    for file in files:
        df = pd.read_csv(file)
        df.columns = df.columns.str.strip()

        if df['Label'].dtype == object:
            df['Label'] = df['Label'].apply(lambda x: 0 if isinstance(x, str) and "BENIGN" in x.upper() else 1)
        else:
            df['Label'] = df['Label'].apply(lambda x: 0 if x == 0 else 1)

        dfs.append(df)
    df_all = pd.concat(dfs, ignore_index=True)
    X = df_all[selected_features_CIC2018].replace([np.inf, -np.inf], np.nan).dropna()
    y = df_all['Label'].loc[X.index]
    return X, y


# načítanie trénovacích a testovacích dát
X_train, y_train = load_and_process(train_files)
X_test, y_test = load_and_processCIC2018(test_files)

# trénovanie modelu
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

# vyhodnotenie
y_pred = rf_model.predict(X_test)
y_train_pred = rf_model.predict(X_train)

train_accuracy = accuracy_score(y_train, y_train_pred)
test_accuracy = accuracy_score(y_test, y_pred)

print(f"Train Accuracy: {train_accuracy:.4f}")
print(f"Test Accuracy on Monday: {test_accuracy:.4f}")

# confusion Matrix
cm = confusion_matrix(y_test, y_pred)
labels = ['Benign', 'Attack']

plt.figure(figsize=(6, 4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels)
plt.xlabel('Predicted Label')
plt.ylabel('True Label')
plt.title('Confusion Matrix')
plt.show()

# classification Report
report = classification_report(y_test, y_pred, target_names=labels)
print("Classification Report:\n", report)