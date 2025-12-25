
# coding: utf-8

# ==============================
# Imports
# ==============================
import struct
import time
import logging
import socket
import csv
import os
import math
import pickle

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.all import Packet, BitField

# ==============================
# Experiment Configuration
# ==============================
# 1 = DP only
# 2 = CP only
# 3 = DP + CP (Hybrid)
EXPERIMENT_MODE = int(os.getenv("EXPERIMENT_MODE", "2"))

DP_THRESHOLD = int(os.getenv("DP_THRESHOLD", "900"))
MERGE_EVERY = int(os.getenv("MERGE_EVERY", "10"))

# If 1: skip reading Lemon bitmaps (layers) to speed up epochs; use CMS only.
FAST_CMS_ONLY = int(os.getenv("FAST_CMS_ONLY", "1"))

# If 1: counters are reset every epoch (recommended). Then per-epoch delta is simply c.
RESET_COUNTERS_EACH_EPOCH = int(os.getenv("RESET_COUNTERS_EACH_EPOCH", "1"))

# CP online learning (River models support learn_one)
ONLINE_LEARN = int(os.getenv("ONLINE_LEARN", "0"))

# Exponential smoothing for burst features
EMA_ALPHA = float(os.getenv("EMA_ALPHA", "0.2"))

# ==============================
# Ground Truth
# ==============================
GT_VICTIM = os.getenv("GT_VICTIM", "192.168.10.50")  # must match attack_gen.py

# ==============================
# Logging
# ==============================
LOG_FILE = {
    1: "experiment_dp_only.log",
    2: "experiment_cp_only.log",
    3: "experiment_hybrid.log",
}.get(EXPERIMENT_MODE, "experiment_unknown.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

# Also print INFO logs to console (so you see progress immediately)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logging.getLogger().addHandler(console)

# ==============================
# Load CVFDT Model (only for CP / Hybrid)
# ==============================
cvfdt = None
if EXPERIMENT_MODE in (2, 3):
    with open("cvfdt_model.pkl", "rb") as f:
        cvfdt = pickle.load(f)
    print("[CVFDT] CIC-trained model loaded")

# ==============================
# Helper Functions
# ==============================

def int_to_ip(num: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", num))


def confusion(pred: int, label: int) -> str:
    if pred == 1 and label == 1:
        return "TP"
    if pred == 1 and label == 0:
        return "FP"
    if pred == 0 and label == 1:
        return "FN"
    return "TN"


def lc(zeros: int, bitmap: int) -> float:
    if zeros == 0:
        return float(bitmap)
    return -float(bitmap) * math.log(zeros / float(bitmap))


def epy(bloom_filter, size: int) -> float:
    total = sum(bloom_filter)
    if total == 0:
        return 0.0
    entropy = 0.0
    for v in bloom_filter:
        if v > 0:
            p = v / total
            entropy -= p * math.log(p, 2)
    return float(entropy)


class CpuHeader(Packet):
    name = "CpuPacket"
    fields_desc = [
        BitField("hash", 0, 32),
        BitField("hash1", 0, 32),
        BitField("srcip", 0, 32),
        BitField("dstip", 0, 32),
        BitField("srcport", 0, 16),
        BitField("dstport", 0, 16),
        BitField("protocol", 0, 8),
        BitField("counter", 0, 32),
        BitField("epoch", 0, 16),
        BitField("outputport", 0, 8),
    ]


class myController(object):
    def __init__(self):
        # ==============================
        # Experiment naming
        # ==============================
        self.exp_name = {
            1: "dp_only",
            2: "cp_only",
            3: "hybrid",
        }.get(EXPERIMENT_MODE, "unknown")

        # ==============================
        # Epoch / event counters
        # ==============================
        self.dp_epoch_digests = 0
        self.dp_to_cp_events = 0
        self._epoch_counter = 0

        # ==============================
        # Confusion matrices (epoch-level)
        # ==============================
        self.cm_dp = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
        self.cm_cp = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

        # CP option-3 (row-level: traffic vs victim)
        self.cm_cp_traffic = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
        self.cm_cp_victim = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

        # ==============================
        # Performance knobs
        # ==============================
        self.entropy_every = int(os.getenv("ENTROPY_EVERY", "5"))
        self.last_entropy = 0.0

        # Lemon / temporal state
        self.prev_lemon = {}       # ip -> last Est
        self.prev_counter = {}     # ip -> last c (only used if counters not reset)

        # NEW: CMS temporal features (per ip)
        self.prev_delta = {}       # ip -> last delta_c
        self.ema_delta = {}        # ip -> EMA of delta_c

        # ==============================
        # CSV outputs (experiment-aware)
        # ==============================
        self.epoch_csv = f"epoch_summary_{self.exp_name}.csv"
        self.out_csv = f"detections_{self.exp_name}.csv"
        self.ml_csv = f"cvfdt_metrics_{self.exp_name}.csv"
        self.cp_epoch_csv = f"cp_epoch_{self.exp_name}.csv"

        self._init_csvs()

        # ==============================
        # Topology & switches
        # ==============================
        self.topo = load_topo("/home/devar/Lemon/bmv2/topology.json")
        self.controllers = {}

        # ==============================
        # Lemon state
        # ==============================
        self.hh_dip = {}
        self.hh_hash = {}

        self.layer1_merge = []
        self.layer2_merge = []
        self.layer3_merge = []
        self.layer4_merge = []
        self.layer5_merge = []

        # ==============================
        # Sketch parameters
        # ==============================
        self.l1_bitmapsize = 8
        self.l2_bitmapsize = 32
        self.l3_bitmapsize = 32
        self.l4_bitmapsize = 32
        self.l5_bitmapsize = 512

        self.sample1 = 16384
        self.sample2 = 8192
        self.sample3 = 1024
        self.sample4 = 256

        self.size1 = 524288
        self.size2 = 65536
        self.size3 = 8192
        self.size4 = 2048
        self.size5 = 1024

        self.heavysize = 8192

        self._reset_merged_sketches()

        # ==============================
        # Connect to switches
        # ==============================
        self.connect_to_switches()

    # ------------------------------
    # CSV init
    # ------------------------------
    def _init_csvs(self):
        if not os.path.exists(self.epoch_csv):
            with open(self.epoch_csv, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["epoch_ts", "epoch_label", "dp_alert", "cp_alert", "dp_digest_events", "rows_logged"]
                )

        if not os.path.exists(self.out_csv):
            with open(self.out_csv, "w", newline="") as f:
                csv.writer(f).writerow(["epoch_ts", "ip", "cm_count", "lemon_est"])

        if EXPERIMENT_MODE in (2, 3):
            if not os.path.exists(self.ml_csv):
                with open(self.ml_csv, "w", newline="") as f:
                    csv.writer(f).writerow(
                        [
                            "epoch_ts",
                            "ip",
                            "role",
                            "cm_count",
                            "delta_c",
                            "lemon_est",
                            "entropy",
                            "delta_lemon",
                            # NEW FEATURES
                            "prev_delta",
                            "ema_delta",
                            "burst_ratio",
                            "log_delta",
                            "dp_pred",
                            "cp_pred",
                            "traffic_label",
                            "victim_label",
                            "traffic_dp_result",
                            "traffic_cp_result",
                            "victim_dp_result",
                            "victim_cp_result",
                        ]
                    )

            if not os.path.exists(self.cp_epoch_csv):
                with open(self.cp_epoch_csv, "w", newline="") as f:
                    csv.writer(f).writerow(
                        [
                            "epoch_ts",
                            "cp_traffic_TP",
                            "cp_traffic_TN",
                            "cp_traffic_FP",
                            "cp_traffic_FN",
                            "cp_victim_TP",
                            "cp_victim_TN",
                            "cp_victim_FP",
                            "cp_victim_FN",
                            "rows_logged",
                        ]
                    )

    # ------------------------------
    # Switch helpers
    # ------------------------------
    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            print("p4switch:", p4switch, "thrift_port:", thrift_port)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

    def _leaf_switches(self):
        # only real switches like s01/s02, skip divider
        return [sw for sw in self.controllers.keys() if len(sw) == 3]

    def reset_counters(self):
        if not RESET_COUNTERS_EACH_EPOCH:
            return
        for sw, ctrl in self.controllers.items():
            if len(sw) != 3:
                continue
            try:
                ctrl.register_reset("counter")
            except Exception as e:
                logging.debug(f"[RESET] failed sw={sw}: {e}")

    def _read_counter_idx(self, p4switch, idx):
        """Fast single-index read of BMv2 register 'counter'."""
        ctrl = self.controllers[p4switch]
        try:
            v = ctrl.register_read("counter", idx)
        except TypeError:
            # older API may not accept idx
            arr = ctrl.register_read("counter")
            return int(arr[idx])
        if isinstance(v, (list, tuple)):
            return int(v[0]) if len(v) else 0
        return int(v)

    # ------------------------------
    # Lemon merge
    # ------------------------------
    def _reset_merged_sketches(self):
        self.layer1_merge = [0] * (self.size1 * self.l1_bitmapsize)
        self.layer2_merge = [0] * (self.size2 * self.l2_bitmapsize)
        self.layer3_merge = [0] * (self.size3 * self.l3_bitmapsize)
        self.layer4_merge = [0] * (self.size4 * self.l4_bitmapsize)
        self.layer5_merge = [0] * (self.size5 * self.l5_bitmapsize)

    def collect_merge(self):
        # Reset merged sketches + HH id per merge window
        self._reset_merged_sketches()
        self.hh_dip.clear()
        self.hh_hash.clear()

        for p4switch in self.topo.get_p4switches():
            if len(p4switch) != 3:
                continue

            ctrl = self.controllers[p4switch]

            heavy_dip = ctrl.register_read("lemon_heavy_id")
            heavy_hash = ctrl.register_read("lemon_heavy_tag")

            # Always read HH; layers optional
            if not FAST_CMS_ONLY:
                layer1 = ctrl.register_read("lemon_layer1")
                layer2 = ctrl.register_read("lemon_layer2")
                layer3 = ctrl.register_read("lemon_layer3")
                layer4 = ctrl.register_read("lemon_layer4")
                layer5 = ctrl.register_read("lemon_layer5")

            # Store heavy-hitter identity only
            for slot in range(self.heavysize):
                if heavy_dip[slot] != 0:
                    self.hh_dip[slot] = heavy_dip[slot]
                    self.hh_hash[slot] = heavy_hash[slot]

            # Merge sketches (bitwise OR)
            if not FAST_CMS_ONLY:
                self.layer1_merge = [a | b for a, b in zip(self.layer1_merge, layer1)]
                self.layer2_merge = [a | b for a, b in zip(self.layer2_merge, layer2)]
                self.layer3_merge = [a | b for a, b in zip(self.layer3_merge, layer3)]
                self.layer4_merge = [a | b for a, b in zip(self.layer4_merge, layer4)]
                self.layer5_merge = [a | b for a, b in zip(self.layer5_merge, layer5)]

    # ------------------------------
    # Entropy
    # ------------------------------
    def entropy(self):
        if FAST_CMS_ONLY:
            # No layers -> no entropy
            self.last_entropy = 0.0
            return

        epy_map = []
        for slot in range(0, self.size1):
            l1_bitmap = self.layer1_merge[
                slot * self.l1_bitmapsize : slot * self.l1_bitmapsize + self.l1_bitmapsize
            ]
            l1_count_0 = self.l1_bitmapsize - sum(l1_bitmap)
            if l1_count_0 > self.l1_bitmapsize * 0.8:
                epy_map.append(lc(l1_count_0, self.l1_bitmapsize))
                continue

            l2_hash = slot % self.size2
            l2_bitmap = self.layer2_merge[
                l2_hash * self.l2_bitmapsize : l2_hash * self.l2_bitmapsize + self.l2_bitmapsize
            ]
            l2_count_0 = self.l2_bitmapsize - sum(l2_bitmap)
            if l2_count_0 > self.l2_bitmapsize * 0.2:
                l2_est = (
                    lc(l2_count_0, self.l2_bitmapsize)
                    * 65536
                    / (65536 - self.sample2)
                    * (65536 / self.sample1)
                )
                epy_map.append(l2_est)
                continue

            l3_hash = slot % self.size3
            l3_bitmap = self.layer3_merge[
                l3_hash * self.l3_bitmapsize : l3_hash * self.l3_bitmapsize + self.l3_bitmapsize
            ]
            l3_count_0 = self.l3_bitmapsize - sum(l3_bitmap)
            if l3_count_0 > self.l3_bitmapsize * 0.2:
                l3_est = (
                    lc(l3_count_0, self.l3_bitmapsize)
                    * 65536
                    / (65536 - self.sample3)
                    * (65536 / self.sample2)
                )
                epy_map.append(l3_est)
                continue

            l4_hash = slot % self.size4
            l4_bitmap = self.layer4_merge[
                l4_hash * self.l4_bitmapsize : l4_hash * self.l4_bitmapsize + self.l4_bitmapsize
            ]
            l4_count_0 = self.l4_bitmapsize - sum(l4_bitmap)
            if l4_count_0 > self.l4_bitmapsize * 0.2:
                l4_est = (
                    lc(l4_count_0, self.l4_bitmapsize)
                    * 65536
                    / (65536 - self.sample4)
                    * (65536 / self.sample3)
                )
                epy_map.append(l4_est)
                continue

            l5_hash = slot % self.size5
            l5_bitmap = self.layer5_merge[
                l5_hash * self.l5_bitmapsize : l5_hash * self.l5_bitmapsize + self.l5_bitmapsize
            ]
            l5_count_0 = self.l5_bitmapsize - sum(l5_bitmap)
            l5_est = lc(l5_count_0, self.l5_bitmapsize) * (65536 / self.sample4)
            epy_map.append(l5_est)

        self.last_entropy = epy(epy_map, self.size1)
        logging.info("entropy_src: %f", self.last_entropy)

    # ------------------------------
    # Feature builder
    # ------------------------------
    def _build_features(self, ip: str, delta_c: int, est: float, delta_lemon: float, entropy_val: float):
        """Features that work even when Lemon Est is 0 (FAST_CMS_ONLY=1)."""
        prev_d = int(self.prev_delta.get(ip, 0))
        ema = float(self.ema_delta.get(ip, 0.0))

        # Update EMA
        ema = (EMA_ALPHA * float(delta_c)) + ((1.0 - EMA_ALPHA) * ema)
        self.ema_delta[ip] = ema
        self.prev_delta[ip] = int(delta_c)

        burst_ratio = float(delta_c) / (ema + 1e-9)
        log_delta = math.log1p(float(delta_c))

        feats = {
            # original
            "cm_count": float(delta_c),
            "lemon_est": float(est),
            "delta_lemon": float(abs(delta_lemon)),
            "entropy": float(entropy_val),
            # NEW (CMS-based)
            "prev_delta": float(prev_d),
            "ema_delta": float(ema),
            "burst_ratio": float(burst_ratio),
            "log_delta": float(log_delta),
        }
        return feats, prev_d, ema, burst_ratio, log_delta

    # ------------------------------
    # Main query
    # ------------------------------
    def query(self):
        epoch_ts = int(time.time())

        ml_rows_buffer = []
        det_rows_buffer = []
        rows_logged = 0

        saw_gt_victim = False
        dp_epoch_digests = 0
        cp_epoch_alert = 0

        # row-level CP option-3 confusion (only for rows we log)
        cp_tr = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
        cp_v = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

        # In CP-only mode, we don't gate by DP_THRESHOLD
        gate_threshold = 0 if EXPERIMENT_MODE == 2 else DP_THRESHOLD

        for hh_id, l1_hash in self.hh_hash.items():
            if hh_id not in self.hh_dip:
                continue

            ip = int_to_ip(self.hh_dip[hh_id])

            # ----------------------------------
            # Lemon estimate (optional)
            # ----------------------------------
            est = 0.0
            if not FAST_CMS_ONLY:
                # fast estimate: only L1 bits
                layer_index = l1_hash % self.size1
                l1_bits = self.layer1_merge[
                    layer_index * self.l1_bitmapsize : layer_index * self.l1_bitmapsize + self.l1_bitmapsize
                ]
                l1_count_0 = self.l1_bitmapsize - l1_bits.count(1)
                l1_est = lc(l1_count_0, self.l1_bitmapsize)
                est = float(l1_est * 65536 / (65536 - self.sample1))

            # ----------------------------------
            # CMS counter (per-epoch)
            # ----------------------------------
            idx = l1_hash % self.size1

            c = 0
            for p4sw in self._leaf_switches():
                try:
                    v = self._read_counter_idx(p4sw, idx)
                except Exception:
                    v = 0
                if v > c:
                    c = v

            if RESET_COUNTERS_EACH_EPOCH:
                delta_c = int(c)
            else:
                prev_c = int(self.prev_counter.get(ip, 0))
                delta_c = max(0, int(c) - prev_c)
                self.prev_counter[ip] = int(c)

            logging.debug(
                f"[DELTA] epoch={self._epoch_counter} ip={ip} idx={idx} c={int(c)} delta={delta_c}"
            )

            # keep victim flag even when gated
            if ip == GT_VICTIM:
                saw_gt_victim = True

            # ----------------------------------
            # Gate escalation
            # ----------------------------------
            if delta_c < gate_threshold:
                continue

            # If here, DP would raise (or CP-only, gate is 0)
            dp_epoch_digests += 1

            role = "victim" if ip == GT_VICTIM else "attacker"
            traffic_label = 1
            victim_label = 1 if ip == GT_VICTIM else 0

            # write detection row
            det_rows_buffer.append([epoch_ts, ip, int(delta_c), float(est)])

            # ----------------------------------
            # DP pred
            # ----------------------------------
            dp_pred = 1 if delta_c >= DP_THRESHOLD else 0

            # ----------------------------------
            # CP pred (only if mode uses CP)
            # ----------------------------------
            cp_pred = 0
            if EXPERIMENT_MODE in (2, 3) and cvfdt is not None:
                last_est = float(self.prev_lemon.get(ip, est))
                delta_lemon = float(est) - last_est
                self.prev_lemon[ip] = float(est)

                feats, prev_d, ema, burst_ratio, log_delta = self._build_features(
                    ip=ip,
                    delta_c=int(delta_c),
                    est=float(est),
                    delta_lemon=float(delta_lemon),
                    entropy_val=float(self.last_entropy),
                )

                # Predict
                y_pred = cvfdt.predict_one(feats)
                cp_pred = int(y_pred) if y_pred is not None else 0
                cp_epoch_alert = 1 if cp_pred == 1 else cp_epoch_alert

                # Online learn (recommended: train with your own labels, not threshold)
                if ONLINE_LEARN:
                    # Use victim_label as the main supervised signal for your setup
                    try:
                        cvfdt.learn_one(feats, victim_label)
                    except Exception as e:
                        logging.debug(f"[LEARN] learn_one failed: {e}")

                # row-level confusion
                traffic_dp_result = confusion(dp_pred, traffic_label)
                traffic_cp_result = confusion(cp_pred, traffic_label)
                victim_dp_result = confusion(dp_pred, victim_label)
                victim_cp_result = confusion(cp_pred, victim_label)

                cp_tr[traffic_cp_result] += 1
                cp_v[victim_cp_result] += 1

                ml_rows_buffer.append(
                    [
                        epoch_ts,
                        ip,
                        role,
                        int(c),
                        int(delta_c),
                        float(est),
                        float(self.last_entropy),
                        float(delta_lemon),
                        int(prev_d),
                        float(ema),
                        float(burst_ratio),
                        float(log_delta),
                        int(dp_pred),
                        int(cp_pred),
                        int(traffic_label),
                        int(victim_label),
                        traffic_dp_result,
                        traffic_cp_result,
                        victim_dp_result,
                        victim_cp_result,
                    ]
                )
                rows_logged += 1

        # ----------------------------------
        # Flush CSV buffers
        # ----------------------------------
        if det_rows_buffer:
            with open(self.out_csv, "a", newline="") as f:
                csv.writer(f).writerows(det_rows_buffer)

        if EXPERIMENT_MODE in (2, 3) and ml_rows_buffer:
            with open(self.ml_csv, "a", newline="") as f:
                csv.writer(f).writerows(ml_rows_buffer)

            # accumulate row-level CP totals
            for k in ("TP", "TN", "FP", "FN"):
                self.cm_cp_traffic[k] += cp_tr[k]
                self.cm_cp_victim[k] += cp_v[k]

            with open(self.cp_epoch_csv, "a", newline="") as f:
                csv.writer(f).writerow(
                    [
                        epoch_ts,
                        cp_tr["TP"],
                        cp_tr["TN"],
                        cp_tr["FP"],
                        cp_tr["FN"],
                        cp_v["TP"],
                        cp_v["TN"],
                        cp_v["FP"],
                        cp_v["FN"],
                        rows_logged,
                    ]
                )

        # ----------------------------------
        # Epoch-level CM logic (3 modes)
        # ----------------------------------
        epoch_label = 1 if saw_gt_victim else 0

        # DP alert means "DP fired (threshold) at least once in this epoch"
        dp_alert = 1 if dp_epoch_digests > 0 else 0

        # CP alert means "CP predicted attack at least once in this epoch"
        cp_alert = 1 if cp_epoch_alert > 0 else 0

        # --- DP-only CM
        if EXPERIMENT_MODE == 1:
            self.cm_dp[confusion(dp_alert, epoch_label)] += 1

        # --- CP-only CM
        elif EXPERIMENT_MODE == 2:
            self.cm_cp[confusion(cp_alert, epoch_label)] += 1

        # --- Hybrid CM
        else:
            self.cm_dp[confusion(dp_alert, epoch_label)] += 1
            # only score CP when DP escalated (same behaviour as before)
            if dp_alert == 1:
                self.cm_cp[confusion(cp_alert, epoch_label)] += 1

        with open(self.epoch_csv, "a", newline="") as f:
            csv.writer(f).writerow(
                [epoch_ts, epoch_label, dp_alert, cp_alert, dp_epoch_digests, rows_logged]
            )

        if EXPERIMENT_MODE in (1, 3):
            logging.info(
                f"[CM_DP_TOTAL] TP={self.cm_dp['TP']} TN={self.cm_dp['TN']} FP={self.cm_dp['FP']} FN={self.cm_dp['FN']}"
            )
        if EXPERIMENT_MODE in (2, 3):
            logging.info(
                f"[CM_CP_TOTAL] TP={self.cm_cp['TP']} TN={self.cm_cp['TN']} FP={self.cm_cp['FP']} FN={self.cm_cp['FN']}"
            )

        self.dp_epoch_digests = dp_epoch_digests


if __name__ == "__main__":
    controller = myController()
    logging.info(f"Controller started | EXPERIMENT_MODE={EXPERIMENT_MODE}")

    EPOCH_LEN = float(os.getenv("EPOCH_LEN", "1.0"))

    try:
        while True:
            epoch_start = time.time()

            t0 = time.time()
            if controller._epoch_counter % MERGE_EVERY == 0:
                controller.collect_merge()
            t_collect = time.time() - t0

            t1 = time.time()
            if EXPERIMENT_MODE in (1, 3) and not FAST_CMS_ONLY:
                if controller.dp_epoch_digests > 0 and controller._epoch_counter % controller.entropy_every == 0:
                    controller.entropy()
            t_entropy = time.time() - t1

            t2 = time.time()
            controller.query()
            t_query = time.time() - t2

            t3 = time.time()
            controller.reset_counters()
            t_reset = time.time() - t3

            controller._epoch_counter += 1

            elapsed = time.time() - epoch_start
            sleep_time = max(0.0, EPOCH_LEN - elapsed)
            time.sleep(sleep_time)

            logging.info(
                f"[TIME_BREAKDOWN] Epoch={controller._epoch_counter} "
                f"collect={t_collect:.6f}s entropy={t_entropy:.6f}s "
                f"query={t_query:.6f}s reset={t_reset:.6f}s "
                f"total={elapsed:.6f}s sleep={sleep_time:.6f}s"
            )


    except KeyboardInterrupt:
        logging.info("Controller stopped by user")
        print("\n[Controller] Stopped by user")

