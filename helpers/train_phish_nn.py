#!/usr/bin/env python3
"""
Train two small MLPs (URL / Content) and report val-loss + val-accuracy.

Run:
  python train_split_models.py --csv dataset_B_05_2020.csv --outdir artifacts
"""

import argparse, json, time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import torch, torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

IGNORE = [
    "whois_registered_domain","domain_registration_length","domain_age",
    "web_traffic","dns_record","google_index","page_rank","status","url",
]

URL_COLS     = slice(0, 56)   # after IGNORE filtering
CONTENT_COLS = slice(56, 80)

class MLP(nn.Module):
    def __init__(self, d_in, widths=(64, 32)):
        """
        Build a feed-forward net of arbitrary depth:
        d_in → widths[0] → … → widths[-1] → 1 → Sigmoid
        """
        super().__init__()
        layers = []
        in_f   = d_in
        for w in widths:
            layers += [nn.Linear(in_f, w), nn.ReLU(), nn.Dropout(0.30)]
            in_f = w
        layers += [nn.Linear(in_f, 1), nn.Sigmoid()]
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)

class ResMLP(nn.Module):
    def __init__(self, d_in):
        super().__init__()
        self.fc1 = nn.Linear(d_in, 48)
        self.fc2 = nn.Linear(48, 24)   # will be added to shortcut
        self.fc3 = nn.Linear(24, 12)
        self.out = nn.Linear(12, 1)
        self.drop = nn.Dropout(0.30)
        self.act  = nn.ReLU()

    def forward(self, x):
        h = self.drop(self.act(self.fc1(x)))
        h = self.fc2(h) + x            # residual add, dims both 24
        h = self.drop(self.act(h))
        h = self.drop(self.act(self.fc3(h)))
        return torch.sigmoid(self.out(h))

class PlainMLP(nn.Module):             # unchanged URL model
    def __init__(self, d_in):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(d_in, 64), nn.ReLU(), nn.Dropout(0.30),
            nn.Linear(64, 32),   nn.ReLU(), nn.Dropout(0.30),
            nn.Linear(32, 1),    nn.Sigmoid()
        )
    def forward(self,x): return self.net(x)

class ResTiny(nn.Module):
    def __init__(self, d_in=24):
        super().__init__()
        self.fc1 = nn.Linear(d_in, 96)
        self.fc2 = nn.Linear(96, 48)
        self.res = nn.Linear(d_in, 48, bias=False)   # match dims for add
        self.fc3 = nn.Linear(48, 24)
        self.fc4 = nn.Linear(24, 12)
        self.out = nn.Linear(12, 1)
        self.act, self.drop = nn.ReLU(), nn.Dropout(0.30)

    def forward(self, x):
        h = self.drop(self.act(self.fc1(x)))
        h = self.drop(self.act(self.fc2(h) + self.res(x)))  # skip-add
        h = self.drop(self.act(self.fc3(h)))
        h = self.act(self.fc4(h))
        return torch.sigmoid(self.out(h))

# --- add near the top ---
class WebPhishCNN(nn.Module):
    """
    1-D CNN version of WebPhish for tabular feature vectors.
    d_in : number of input features (80 for URL / 24 for Content)
    """
    def __init__(self, d_in, num_filters=32, k=3, p_drop=0.3):
        super().__init__()
        self.conv = nn.Conv1d(1, num_filters, k, padding=k//2)
        self.act  = nn.ReLU()
        self.pool = nn.AdaptiveMaxPool1d(1)          # global-max
        self.fc1  = nn.Linear(num_filters, 32)
        self.fc2  = nn.Linear(32, 1)
        self.drop = nn.Dropout(p_drop)

    def forward(self, x):
        # x : [B, d_in]  ->  [B, 1, d_in]
        h = self.conv(x.unsqueeze(1))                 # [B, C, d_in]
        h = self.act(h)
        h = self.pool(h).squeeze(-1)                  # [B, C]
        h = self.drop(self.act(self.fc1(h)))
        return torch.sigmoid(self.fc2(h))


# focal-BCE
def focal_loss(p, y, α=0.25, γ=2.0, eps=1e-6):
    p = torch.clamp(p, eps, 1.0-eps)
    ce = -(y*torch.log(p) + (1-y)*torch.log(1-p))
    pt = torch.where(y==1, p, 1-p)
    return (α * (1-pt)**γ * ce).mean()


def epoch_stats(loader, model, lossf, dev):
    model.eval()
    losses, correct, total = [], 0, 0
    with torch.no_grad():
        for xb, yb in loader:
            xb, yb = xb.to(dev), yb.to(dev)
            preds = model(xb)
            losses.append(lossf(preds, yb).item())
            correct += ((preds >= 0.5) == (yb >= 0.5)).sum().item()
            total   += yb.size(0)
    return np.mean(losses), correct / total

def train_one(
        name,                 # "url_model" | "content_model"
        X, y, outdir,         # data slice + labels
        *,                    # force keyword args after here
        build_fn,             # callable(d_in) -> nn.Module  (required)
        loss_type="bce",      # "bce" | "focal"
        pos_w=1.0,            # pos-class weight for BCE
        patience=8,           # early-stop patience
        batch=256, epochs=60  # training schedule
    ):

    scaler = StandardScaler();  X = scaler.fit_transform(X)
    Xtr, Xva, ytr, yva = train_test_split(
        X, y, test_size=.20, stratify=y, random_state=42)

    # ------------- bring these two lines back -----------------
    tr = DataLoader(
        TensorDataset(torch.tensor(Xtr, dtype=torch.float32),
                      torch.tensor(ytr, dtype=torch.float32).unsqueeze(1)),
        batch_size=256, shuffle=True)

    va = DataLoader(
        TensorDataset(torch.tensor(Xva, dtype=torch.float32),
                      torch.tensor(yva, dtype=torch.float32).unsqueeze(1)),
        batch_size=256)
    # ----------------------------------------------------------

    # pick architecture
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if build_fn is None:
        model = WebPhishCNN(X.shape[1])              # default
    else:
        model = build_fn(X.shape[1])
    opt   = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)

    pos_weight = torch.tensor([pos_w], device=dev)
    if loss_type == "focal":
        def lossf(pred, tgt): return focal_loss(pred, tgt, α=0.25, γ=2.0)
    else:                                    # standard BCE
        if pos_w != 1.0:
            pos_weight = torch.tensor([pos_w], device=dev)
            lossf = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        else:
            lossf = nn.BCELoss()

    # … rest of the loop unchanged …

    best_loss, best_acc, wait = 9e9, 0.0, patience
    for ep in range(1, epochs + 1):
        model.train()
        for xb, yb in tr:
            xb, yb = xb.to(dev), yb.to(dev)
            opt.zero_grad()
            loss = lossf(model(xb), yb)
            loss.backward(); opt.step()

        v_loss, v_acc = epoch_stats(va, model, lossf, dev)
        print(f"{name:14} ep{ep:02d}  loss={v_loss:.4f}  acc={v_acc*100:5.2f}%")

        if v_loss < best_loss:
            best_loss, best_acc, wait = v_loss, v_acc, patience
            torch.save(model.state_dict(), outdir / f"{name}.pt")
        else:
            wait -= 1
            if wait == 0:
                break

    print(f"✔ {name} best loss={best_loss:.4f} acc={best_acc*100:5.2f}%\n")
    
    # save scaler
    (outdir/f"scaler_{name}.json").write_text(
        json.dumps({"mean": scaler.mean_.tolist(),
                    "std":  scaler.scale_.tolist()}))

    # export ONNX
    dummy = torch.randn(1, X.shape[1])
    torch.onnx.export(model.cpu(), dummy, outdir/f"{name}.onnx",
                      input_names=["x"], output_names=["y"],
                      dynamic_axes={"x": {0: "b"}, "y": {0: "b"}},
                      opset_version=12)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--outdir", default="artifacts")
    ns = ap.parse_args()

    out = Path(ns.outdir); out.mkdir(exist_ok=True)
    raw = pd.read_csv(ns.csv)
    y   = (raw["status"] == "phishing").astype(np.float32).values
    X   = raw.drop(columns=IGNORE).values.astype(np.float32)

    train_one(
        "url_model", X[:, URL_COLS], y, out,
        build_fn=lambda d: ResTiny(d),
        loss_type="focal", pos_w=1.0, patience=5)

    # train_one(
    #     "content_model", X[:, CONTENT_COLS], y, out,
    #     build_fn=lambda d: ResTiny(d),
    #     loss_type="focal", pos_w=1.0, patience=10)



if __name__ == "__main__":
    main()
