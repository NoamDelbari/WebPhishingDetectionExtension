# train_content_lgbm.py  (run once)
import json, argparse, joblib, lightgbm as lgb
import pandas as pd, numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from onnxmltools import convert_lightgbm              # ← NEW
from skl2onnx import convert_sklearn        # works for both LGBM & pipelines
from skl2onnx.common.data_types import FloatTensorType

IGNORE = ["whois_registered_domain","domain_registration_length","domain_age",
          "web_traffic","dns_record","google_index","page_rank","status","url",
          "ratio_intRedirection","ratio_extRedirection"]
CONTENT_COLS = slice(56, 80)               # after drop(IGNORE)

ap = argparse.ArgumentParser()
ap.add_argument("--csv", required=True)
ap.add_argument("--outdir", default="artifacts")
ns = ap.parse_args(); out = Path(ns.outdir); out.mkdir(exist_ok=True)

df  = pd.read_csv(ns.csv).drop(columns=IGNORE)
print(f"Content cols: {df.columns[CONTENT_COLS]}")
X   = df.values.astype(np.float32)[:, CONTENT_COLS]
y   = (pd.read_csv(ns.csv)["status"]=="phishing").astype(np.int32).values

# scale numeric cols (tree depth is small, scaling helps a bit)
scaler = StandardScaler().fit(X)
X = scaler.transform(X)

Xtr, Xva, ytr, yva = train_test_split(
    X, y, test_size=.20, stratify=y, random_state=42)

lgbm = lgb.LGBMClassifier(
        n_estimators=400, learning_rate=0.05,
        num_leaves=64, subsample=0.8, colsample_bytree=0.8,
        max_depth=-1, objective="binary", n_jobs=-1)

lgbm.fit(Xtr, ytr, eval_set=[(Xva,yva)], eval_metric="auc")

print("val-accuracy:",
      (lgbm.predict(Xva) == yva).mean().round(4))

# Save model + scaler
joblib.dump(lgbm,  out/"content_lgbm.pkl")
json.dump({"mean": scaler.mean_.tolist(),
           "std":  scaler.scale_.tolist()},
          open(out/"scaler_content_lgbm.json","w"))

initial = [("x", FloatTensorType([None, X.shape[1]]))]
onx = convert_lightgbm(
        lgbm,                    # fitted model
        initial_types=initial,
        zipmap=False,            # disable ZipMap so ORT gets a tensor
        target_opset=13)
open(f"{out}/content_lgbm.onnx","wb").write(onx.SerializeToString())

Path(f"{out}/content_lgbm.onnx").write_bytes(onx.SerializeToString())
print("✔  ZipMap removed:",
      all(n.op_type != "ZipMap" for n in onx.graph.node))

import onnx

m = onnx.load(f"{out}/content_lgbm.onnx")
assert "ZipMap" not in [n.op_type for n in m.graph.node]
print("✔ tensor output, ready for onnxruntime-web")
