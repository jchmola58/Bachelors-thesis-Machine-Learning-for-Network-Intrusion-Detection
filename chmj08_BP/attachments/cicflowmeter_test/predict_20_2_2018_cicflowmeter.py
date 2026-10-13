import pandas as pd
import numpy as np
import joblib
import tensorflow as tf

# cesta k CSV
input_csv = r"C:\Users\jchmo\pcap\pcap\prejdene_logy_cicflowmetrom\combined_features_only.csv"

# cesta k modelom a scaleru
scaler_path = "C:/Users/jchmo/OneDrive/Počítač/vse/bakalar/ensemble_model/scaler.pkl"
rf_model_path = "C:/Users/jchmo/OneDrive/Počítač/vse/bakalar/ensemble_model/rf_model.pkl"
nn_model_path = "C:/Users/jchmo/OneDrive/Počítač/vse/bakalar/ensemble_model/nn_model.keras"

# focal loss pre načítanie modelu
def focal_loss(gamma=2., alpha=0.25):
    def focal_loss_fixed(y_true, y_pred):
        BCE = tf.keras.losses.binary_crossentropy(y_true, y_pred)
        pt = tf.keras.backend.exp(-BCE)
        return alpha * (1 - pt) ** gamma * BCE
    return focal_loss_fixed

# načítanie modelov
scaler = joblib.load(scaler_path)
rf_model = joblib.load(rf_model_path)
nn_model = tf.keras.models.load_model(nn_model_path, custom_objects={'focal_loss_fixed': focal_loss()}, compile=False)

# mapovanie názvov stĺpcov
column_mapping = {
    'Pkt Size Avg': 'Average Packet Size',
    'Pkt Len Max': 'Max Packet Length',
    'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
    'Bwd Pkt Len Max': 'Bwd Packet Length Max',
    'Pkt Len Mean': 'Packet Length Mean',
    'Bwd Pkt Len Std': 'Bwd Packet Length Std',
    'Pkt Len Var': 'Packet Length Variance',
    'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
    'Bwd Pkt Len Mean': 'Bwd Packet Length Mean',
    'Pkt Len Std': 'Packet Length Std',
    'Subflow Fwd Byts': 'Subflow Fwd Bytes',
    'Fwd Pkt Len Max': 'Fwd Packet Length Max',
    'Fwd Pkt Len Min': 'Fwd Packet Length Min',
    'TotLen Fwd Pkts': 'Total Length of Fwd Packets',
    'TotLen Bwd Pkts': 'Total Length of Bwd Packets',
}

# definované features v správnom poradí
selected_features = list(column_mapping.values())

# načítanie dát
df = pd.read_csv(input_csv)

# premenovanie stĺpcov
df = df.rename(columns=column_mapping)

# kontrola, aby tam boli všetky potrebné featury
for feature in selected_features:
    if feature not in df.columns:
        df[feature] = 0.0

# výber a škálovanie dát
X = df[selected_features]
X_scaled = scaler.transform(X)

# predikcia 
probas_rf = rf_model.predict_proba(X_scaled)[:, 1]
probas_nn = nn_model.predict(X_scaled).flatten()

# kombinácia modelov
rf_probs_adj = probas_rf / 0.6
nn_probs_adj = probas_nn / 0.5

ensemble_probs = 0.4 * rf_probs_adj + 0.6 * nn_probs_adj

# threshold
ensemble_preds = (ensemble_probs >= 0.5).astype(int)

# uloženie výsledkov
output_df = pd.DataFrame({
    'proba_rf': probas_rf,
    'proba_nn': probas_nn,
    'ensemble_probability': ensemble_probs,
    'prediction': ensemble_preds
})

output_csv = r"C:\Users\jchmo\pcap\pcap\prejdene_logy_cicflowmetrom\ensemble_predictions_final.csv"
output_df.to_csv(output_csv, index=False)
