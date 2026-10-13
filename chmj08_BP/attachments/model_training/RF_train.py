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
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import GroupShuffleSplit, GridSearchCV
from sklearn.tree import plot_tree
import shap
from sklearn.metrics import roc_auc_score


# načítanie a príprava dát
file_paths = [
    "archive/Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "archive/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "archive/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "archive/Wednesday-workingHours.pcap_ISCX.csv",
    "archive/Tuesday-WorkingHours.pcap_ISCX.csv",
    "archive/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "archive/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
]

flow_features = [
    'Destination Port', 'Flow Duration',
    'Total Fwd Packets', 'Total Backward Packets',  
    'Fwd Header Length', 'Bwd Header Length'
]

selected_features = [
    'Average Packet Size', 'Max Packet Length', 'Avg Bwd Segment Size',
    'Bwd Packet Length Max', 'Packet Length Mean',
    'Bwd Packet Length Std', 'Packet Length Variance',
    'Avg Fwd Segment Size', 'Bwd Packet Length Mean', 'Packet Length Std',
    'Subflow Fwd Bytes', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets'
]

dataframes = []
for file in file_paths:
    df = pd.read_csv(file)
    df.columns = df.columns.str.strip()
    if df['Label'].dtype == object:
        df['Label'] = df['Label'].apply(lambda x: 0 if isinstance(x, str) and "BENIGN" in x.upper() else 1)
    else:
        df['Label'] = df['Label'].apply(lambda x: 0 if x == 0 else 1)
    dataframes.append(df)

df = pd.concat(dataframes, ignore_index=True)
df['Flow_ID'] = df[flow_features].astype(str).agg('-'.join, axis=1)

gss = GroupShuffleSplit(test_size=0.3, n_splits=1, random_state=42)
train_idx, test_idx = next(gss.split(df, groups=df['Flow_ID']))
train_df = df.iloc[train_idx]
test_df = df.iloc[test_idx]

X_train = train_df[selected_features]
y_train = train_df['Label']
X_test = test_df[selected_features]
y_test = test_df['Label']

# čistenie
X_train = X_train.replace([np.inf, -np.inf], np.nan).fillna(0)
X_test = X_test.replace([np.inf, -np.inf], np.nan).fillna(0)

# škálovanie
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)


# model RF
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
rf_model.fit(X_train_scaled, y_train)


'''
# predikce s custom threshold
y_probs = rf_model.predict_proba(X_test_scaled)[:, 1]
y_pred_custom = (y_probs >= 0.6).astype(int) 

print("Classification Report (custom threshold 0.6):\n")
print(classification_report(y_test, y_pred_custom))

# porovnanie s klasickým threshold
y_pred = rf_model.predict(X_test_scaled)
print(f"\n🔎 OOB Score: {rf_model.oob_score_:.4f}")
print("\nClassification Report (standard threshold 0.5):\n")
print(classification_report(y_test, y_pred))

y_probs1 = rf_model.predict_proba(X_test_scaled)[:, 1]
y_pred_custom1 = (y_probs1 >= 0.4).astype(int)

print("Classification Report (custom threshold 0.4):\n")
print(classification_report(y_test, y_pred_custom1))

acc = accuracy_score(y_test, y_pred_custom)
prec = precision_score(y_test, y_pred_custom)
rec = recall_score(y_test, y_pred_custom)
f1 = f1_score(y_test, y_pred_custom)

print(f"Accuracy:  {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall:    {rec:.4f}")
print(f"F1-score:  {f1:.4f}")

# confusion matrix
plt.figure(figsize=(6, 4))
sns.heatmap(confusion_matrix(y_test, y_pred_custom), annot=True, fmt='d',
            cmap='Blues', xticklabels=["BENIGN", "ATTACK"],
            yticklabels=["BENIGN", "ATTACK"])
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.show()

# OOB
oob_probs = rf_model.oob_decision_function_[:, 1]
oob_auc = roc_auc_score(y_train, oob_probs)
print(f"OOB ROC AUC: {oob_auc:.4f}")

# test predikcie na správne škálovaných dátach
test_probs = rf_model.predict_proba(X_test_scaled)[:, 1]
test_auc = roc_auc_score(y_test, test_probs)
print(f"Test ROC AUC: {test_auc:.4f}")

# uloženie scaleru
joblib.dump(scaler, 'scaler_final.pkl')

# uloženie modelu
joblib.dump(rf_model, 'random_forest_model_final.pkl')
'''