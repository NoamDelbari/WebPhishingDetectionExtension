import argparse, json
import pandas as pd, numpy as np
from pathlib import Path
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix

import onnxruntime as ort

# --- Import constants from train_phish_nn.py ---
from train_phish_nn import IGNORE, URL_COLS, CONTENT_COLS

def compute_metrics(y_true, y_pred):
    acc = accuracy_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred, average='weighted')
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    tpr = tp / (tp + fn) if (tp + fn) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0
    return acc, tpr, fpr, f1

def load_scaler(scaler_path):
    with open(scaler_path) as f:
        d = json.load(f)
    class DummyScaler:
        def __init__(self, mean, std): self.mean_ = np.array(mean); self.scale_ = np.array(std)
        def transform(self, X): return (X - self.mean_) / self.scale_
    return DummyScaler(d["mean"], d["std"])

def onnx_predict(onnx_path, X):
    sess = ort.InferenceSession(str(onnx_path))
    input_name = sess.get_inputs()[0].name
    out = sess.run(None, {input_name: X.astype(np.float32)})[0]
    return (out >= 0.5).astype(np.int32).flatten()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--lgbm", default="SimpleExtension/model/content_lgbm.onnx")
    ap.add_argument("--lgbm-scaler", default="SimpleExtension/model/scaler_content_lgbm.json")
    ap.add_argument("--nn", default="SimpleExtension/model/url_model.onnx")
    ap.add_argument("--nn-scaler", default="SimpleExtension/model/scaler_url_model.json")
    ns = ap.parse_args()

    df = pd.read_csv(ns.csv).drop(columns=IGNORE)
    y = (pd.read_csv(ns.csv)["status"]=="phishing").astype(np.int32).values

    # LightGBM ONNX (Content columns)
    X_content = df.values.astype(np.float32)[:, CONTENT_COLS]
    scaler_lgbm = load_scaler(ns.lgbm_scaler)
    X_lgbm = scaler_lgbm.transform(X_content)
    y_pred_lgbm = onnx_predict(ns.lgbm, X_lgbm)
    acc, tpr, fpr, f1 = compute_metrics(y, y_pred_lgbm)
    print("LightGBM ONNX (Content):")
    print(f"  Accuracy: {acc:.4f}")
    print(f"  TPR:      {tpr:.4f}")
    print(f"  FPR:      {fpr:.4f}")
    print(f"  F1 Score: {f1:.4f}")

    # Neural Net ONNX (URL columns)
    X_url = df.values.astype(np.float32)[:, URL_COLS]
    scaler_nn = load_scaler(ns.nn_scaler)
    X_nn = scaler_nn.transform(X_url)
    y_pred_nn = onnx_predict(ns.nn, X_nn)
    acc, tpr, fpr, f1 = compute_metrics(y, y_pred_nn)
    print("Neural Net ONNX (URL):")
    print(f"  Accuracy: {acc:.4f}")
    print(f"  TPR:      {tpr:.4f}")
    print(f"  FPR:      {fpr:.4f}")
    print(f"  F1 Score: {f1:.4f}")

    # Union: if either model says phishing (1), result is 1, else 0
    y_pred_union = ((y_pred_lgbm == 1) | (y_pred_nn == 1)).astype(np.int32)
    acc, tpr, fpr, f1 = compute_metrics(y, y_pred_union)
    print("Union (either model says phishing):")
    print(f"  Accuracy: {acc:.4f}")
    print(f"  TPR:      {tpr:.4f}")
    print(f"  FPR:      {fpr:.4f}")
    print(f"  F1 Score: {f1:.4f}")

    # Intersection: only if both models say phishing (1), result is 1, else 0
    y_pred_intersection = ((y_pred_lgbm == 1) & (y_pred_nn == 1)).astype(np.int32)
    acc, tpr, fpr, f1 = compute_metrics(y, y_pred_intersection)
    print("Intersection (both models must say phishing):")
    print(f"  Accuracy: {acc:.4f}")
    print(f"  TPR:      {tpr:.4f}")
    print(f"  FPR:      {fpr:.4f}")
    print(f"  F1 Score: {f1:.4f}")

    # Get probabilities instead of binary predictions
    def onnx_predict_proba(onnx_path, X):
        sess = ort.InferenceSession(str(onnx_path))
        input_name = sess.get_inputs()[0].name
        out = sess.run(None, {input_name: X.astype(np.float32)})[0]
        return out.flatten()  # probabilities

    # Get probabilities
    proba_lgbm = onnx_predict_proba(ns.lgbm, X_lgbm)
    proba_nn   = onnx_predict_proba(ns.nn, X_nn)

    # Weighted average (example: 0.7 for LGBM, 0.3 for NN)
    w_lgbm = 0.3
    w_nn = 0.7
    proba_weighted = w_lgbm * proba_lgbm + w_nn * proba_nn
    y_pred_weighted = (proba_weighted >= 0.5).astype(np.int32)

    acc, tpr, fpr, f1 = compute_metrics(y, y_pred_weighted)
    print(f"Weighted average (LGBM {w_lgbm:.2f}, NN {w_nn:.2f}):")
    print(f"  Accuracy: {acc:.4f}")
    print(f"  TPR:      {tpr:.4f}")
    print(f"  FPR:      {fpr:.4f}")
    print(f"  F1 Score: {f1:.4f}")

if __name__ == "__main__":
    main()
