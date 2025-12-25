# train.py

import csv
import pickle
import random
import math

from river import tree, metrics

INPUT_CSV = "raw_logs.csv"
MODEL_OUT = "cvfdt_model.pkl"

# ------------------------------
# Load data
# ------------------------------
X = []
y = []

with open(INPUT_CSV, "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        features = {
            "delta_c": float(row["delta_c"]),
            "ema_delta": float(row["ema_delta"]),
            "burst_ratio": float(row["burst_ratio"]),
            "log_delta": float(row["log_delta"]),
        }
        label = int(row["label"])
        X.append(features)
        y.append(label)

print(f"[INFO] Loaded {len(X)} samples")

# ------------------------------
# Shuffle & split (80/20)
# ------------------------------
data = list(zip(X, y))
random.shuffle(data)

split = int(0.8 * len(data))
train_data = data[:split]
test_data = data[split:]

# ------------------------------
# Model (CVFDT / Hoeffding Tree)
# ------------------------------
model = tree.HoeffdingAdaptiveTreeClassifier(
    grace_period=50,
    delta=1e-5,
    leaf_prediction="nb",
)

metric = metrics.Accuracy()

# ------------------------------
# Train
# ------------------------------
for x, label in train_data:
    y_pred = model.predict_one(x)
    if y_pred is not None:
        metric.update(label, y_pred)
    model.learn_one(x, label)

print(f"[TRAIN] Accuracy (online estimate): {metric.get():.4f}")

# ------------------------------
# Test
# ------------------------------
test_metric = metrics.Accuracy()

for x, label in test_data:
    y_pred = model.predict_one(x)
    if y_pred is None:
        y_pred = 0
    test_metric.update(label, y_pred)

print(f"[TEST] Accuracy: {test_metric.get():.4f}")

# ------------------------------
# Save model
# ------------------------------
with open(MODEL_OUT, "wb") as f:
    pickle.dump(model, f)

print(f"[SAVED] Model written to {MODEL_OUT}")
