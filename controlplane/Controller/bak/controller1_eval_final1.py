
#coding:utf-8
from calendar import EPOCH
from xml.dom.expatbuilder import theDOMImplementation
import struct
import threading
import time
import logging
import heapq

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI

from scapy.all import Ether, sniff, Packet, BitField, IP, sendp, raw
import csv
import os
import math
import numpy as np
import pickle
DP_THRESHOLD = 1000
# ================= Ground Truth Config =================
GT_VICTIM = "192.168.10.50"   # must match attack_gen.py
# =======================================================
# Optional: epoch-level ground truth window (set in controller.py or via env)
# If you don't set these, epoch_label will fall back to (victim_ip == GT_VICTIM) when available.
#ATTACK_START = int(os.getenv('ATTACK_START', '0'))
#ATTACK_END = int(os.getenv('ATTACK_END', str(10**18)))
# =======================================================
logging.basicConfig(filename='example_lemon_only.log', level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")


with open("cvfdt_cp_model.pkl", "rb") as f:
    cvfdt = pickle.load(f)

print("[CVFDT] CIC-trained model loaded")


def lemon_to_cic_features(cm_count, lemon_est, delta_lemon, entropy):
    return {
        "cm_count": float(cm_count),
        "lemon_est": float(lemon_est),
        "delta_lemon": float(abs(delta_lemon)),
        "entropy": float(entropy)
    }


def get_true_label(victim_ip, epoch_ts):
    if victim_ip == GT_VICTIM:
        return 1
    else:
        return 0

    return 0

def get_epoch_label(epoch_ts, saw_gt_victim=False):
    """Epoch ground-truth label.
    1 = attack window, 0 = benign window.
    Uses ATTACK_START/ATTACK_END if configured; otherwise falls back to whether GT victim was observed.
    
    if ATTACK_START <= int(epoch_ts) <= ATTACK_END:
        return 1
    """
    return 1 if saw_gt_victim else 0

def confusion(pred, label):
    if pred == 1 and label == 1:
        return "TP"
    if pred == 1 and label == 0:
        return "FP"
    if pred == 0 and label == 1:
        return "FN"
    return "TN"



def int_to_ip(num):
    return '.'.join([
        str(num >> 24 & 0xFF),
        str(num >> 16 & 0xFF),
        str(num >> 8 & 0xFF),
        str(num & 0xFF)
    ])


def lc(zeros, bitmap):
    m = bitmap
    V = zeros
    if V == 0:
        return m
    return -m * (math.log(V / m))


def epy(bloom_filter, size):
    total_elements = sum(bloom_filter)
    probabilities = [count / total_elements if total_elements > 0 else 0 for count in bloom_filter]
    entropy = 0
    for prob in probabilities:
        if prob > 0:
            entropy -= prob * math.log(prob, 2)
    return entropy


def epy_old(counter, size):  # return the number of 1 in bitmap
    counter_dst = [0] * int(round(max(counter)))
    num0 = 0
    for i in range(0, size):
        cnt = int(round(counter[i]))
        if cnt == 0:
            num0 = num0 + 1
            continue
        counter_dst[cnt - 1] = counter_dst[cnt - 1] + 1

    n_ini = int(round(max(counter))) - num0
    m = size
    lambda_all = n_ini / m

    counter_dst_em = [0] * int(round(max(counter)))
    counter_dst_em[512:int(round(max(counter))) - 1] = counter_dst[512:int(round(max(counter))) - 1]
    counter_dst_em[0] = counter_dst[0]

    for i in range(1, int(max(counter) / 2)):
        if counter_dst[i] == 0:
            continue
        sp1 = 0
        sp2 = 0
        sump = 0
        for j in range(0, int((i + 1) / 2) + 1):
            sp1 = float(j)
            sp2 = float(i - j + 1)
            p = ((sp1 / m) ** 1) * ((sp2 / m) ** 1)
            if j == 0:
                p = ((sp2 / m) ** 2)
            sump = sump + p

        for j in range(0, int(i / 2) + 1):
            sp1 = float(j)
            sp2 = float(i - j + 1)
            p = ((sp1 / m) ** 1) * ((sp2 / m) ** 1)
            if j == 0:
                p = ((sp2 / m) ** 2)

            if (sp1 == 0):
                counter_dst_em[int(sp2)] = counter_dst_em[int(sp2)] + p / sump * counter_dst[i]
            else:
                counter_dst_em[int(sp1)] = counter_dst_em[int(sp1)] + p / sump * counter_dst[i]
                counter_dst_em[int(sp2)] = counter_dst_em[int(sp2)] + p / sump * counter_dst[i]

    entropy_em = 0.0
    for i in range(0, int(round(max(counter)))):
        entropy_em = entropy_em + counter_dst_em[i] * (float(i + 1) / sum(counter)) * math.log(sum(counter) / float(i + 1), 2)

    return entropy_em


def checkbitmap(item):  # return the number of 1 in bitmap
    ones = 0
    part = bin(item)[2:]
    for i in range(0, len(part)):
        if part[i] == '1':
            ones = ones + 1
    return ones


class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [
        BitField('hash', 0, 32),
        BitField('hash1', 0, 32),
        BitField('srcip', 0, 32),
        BitField('dstip', 0, 32),
        BitField('srcport', 0, 16),
        BitField('dstport', 0, 16),
        BitField('protocol', 0, 8),
        BitField('counter', 0, 32),
        BitField('epoch', 0, 16),
        BitField('outputport', 0, 8)
    ]


class myController(object):
    def __init__(self):
        self.dp_epoch_digests = 0
        self.dp_to_cp_events = 0
        # --- Epoch-level accounting (so confusion matrix includes 'no alert / nothing sent')
        self.epoch_len_sec = 3  # keep in sync with EPOCH_LEN below
        self.epoch_csv = "epoch_summary.csv"

        self.cp_epoch_csv = "cp_option3_epoch.csv"
        if not os.path.exists(self.cp_epoch_csv):
            with open(self.cp_epoch_csv, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow([
                    "epoch_ts",
                    "cp_traffic_TP","cp_traffic_TN","cp_traffic_FP","cp_traffic_FN",
                    "cp_victim_TP","cp_victim_TN","cp_victim_FP","cp_victim_FN",
                    "rows_logged"
                ])

        self.cm_dp = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
        self.cm_cp = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
        # --- CP Option-3 accounting (traffic detection vs victim attribution)
        self.cm_cp_traffic = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
        self.cm_cp_victim  = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

        self.last_epoch_ts = None
        # --- performance knobs
        self.entropy_every = int(os.getenv('ENTROPY_EVERY', '5'))
        self._epoch_counter = 0

        if not os.path.exists(self.epoch_csv):
            with open(self.epoch_csv, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow([
                    "epoch_ts",
                    "epoch_label",
                    "dp_alert",
                    "cp_alert",
                    "dp_digest_events",
                    "rows_logged"
                ])
        self.out_csv = "detections.csv"
        if not os.path.exists(self.out_csv):
            with open(self.out_csv, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["epoch_ts", "ip", "cm_count", "lemon_est"])
        self.prev_lemon = {}
        self.last_entropy = 0.0
        self.topo = load_topo("/home/devar/Lemon/lemon_bmv2/topology.json")
        self.controllers = {}

        self.hh_dip = {}
        self.hh_hash = {}
        self.hh_count = {}
        self.layer1 = {}
        self.layer2 = {}
        self.layer3 = {}
        self.layer4 = {}
        self.layer5 = {}
        self.counter = {}

        self.l1_bitmapsize = 8
        self.l2_bitmapsize = 32
        self.l3_bitmapsize = 32
        self.l4_bitmapsize = 32
        self.l5_bitmapsize = 512

        self.sample1 = 16384
        self.sample2 = 8192
        self.sample3 = 1024
        self.sample4 = 256

        size1 = 524288
        size2 = 65536
        size3 = 8192
        size4 = 2048
        size5 = 1024

        self.size1 = size1
        self.size2 = size2
        self.size3 = size3
        self.size4 = size4
        self.size5 = size5

        self.layer1_merge = [0] * size1 * self.l1_bitmapsize
        self.layer2_merge = [0] * size2 * self.l2_bitmapsize
        self.layer3_merge = [0] * size3 * self.l3_bitmapsize
        self.layer4_merge = [0] * size4 * self.l4_bitmapsize
        self.layer5_merge = [0] * size5 * self.l5_bitmapsize

        self.heavysize = 8192
        self.connect_to_switches()

    def collect_merge(self):
        self.layer1_merge = [0] * (self.size1 * self.l1_bitmapsize)
        self.layer2_merge = [0] * (self.size2 * self.l2_bitmapsize)
        self.layer3_merge = [0] * (self.size3 * self.l3_bitmapsize)
        self.layer4_merge = [0] * (self.size4 * self.l4_bitmapsize)
        self.layer5_merge = [0] * (self.size5 * self.l5_bitmapsize)
        self.hh_dip = {}
        self.hh_hash = {}
        self.hh_count = {}
        for p4switch in self.topo.get_p4switches():
            if (len(p4switch) == 4):
                continue
            if (len(p4switch) > 4):
                continue
            heavy_dip = self.controllers[p4switch].register_read("lemon_heavy_id")
            heavy_hash = self.controllers[p4switch].register_read("lemon_heavy_tag")
            self.layer1[p4switch] = self.controllers[p4switch].register_read("lemon_layer1")
            self.layer2[p4switch] = self.controllers[p4switch].register_read("lemon_layer2")
            self.layer3[p4switch] = self.controllers[p4switch].register_read("lemon_layer3")
            self.layer4[p4switch] = self.controllers[p4switch].register_read("lemon_layer4")
            self.layer5[p4switch] = self.controllers[p4switch].register_read("lemon_layer5")
            #self.counter[p4switch] = self.controllers[p4switch].register_read("counter")  # CM-added on

            # finish collecting, merge heavy
            for slot in range(0, self.heavysize):
                if heavy_dip[slot] != 0 and (slot not in self.hh_dip.keys()):
                    for hh_id, (dip, l1_hash) in self.hh_dip.items():
                        self.hh_count[slot] = self.counter[p4switch][heavy_hash[slot] % self.size1]   
                elif heavy_dip[slot] != 0 and (slot in self.hh_dip.keys()):
                    if self.counter[p4switch][heavy_hash[slot] % self.size1] > self.hh_count[slot]:
                        self.hh_dip[slot] = heavy_dip[slot]  # update
                        self.hh_hash[slot] = heavy_hash[slot]
                        self.hh_count[slot] = self.counter[p4switch][heavy_hash[slot] % self.size1]
                    else:
                        continue
                else:
                    continue

            # We used a simple loop for functional testing, which required a longer merge time.
            self.layer1_merge = [a | b for a, b in zip(self.layer1_merge, self.layer1[p4switch])]
            self.layer2_merge = [a | b for a, b in zip(self.layer2_merge, self.layer2[p4switch])]
            self.layer3_merge = [a | b for a, b in zip(self.layer3_merge, self.layer3[p4switch])]
            self.layer4_merge = [a | b for a, b in zip(self.layer4_merge, self.layer4[p4switch])]
            self.layer5_merge = [a | b for a, b in zip(self.layer5_merge, self.layer5[p4switch])]

    def query_with_hash(self, l1_hash):
        layer1 = {}
        layer1_switch = self.layer1_merge
        layer_index = l1_hash % self.size1
        layer1[layer_index] = layer1_switch[layer_index * self.l1_bitmapsize:layer_index * self.l1_bitmapsize + self.l1_bitmapsize]

        layer2 = {}
        layer2_switch = self.layer2_merge
        layer_index = l1_hash % self.size2
        layer2[layer_index] = layer2_switch[layer_index * self.l2_bitmapsize:layer_index * self.l2_bitmapsize + self.l2_bitmapsize]

        layer3 = {}
        layer3_switch = self.layer3_merge
        layer_index = l1_hash % self.size3
        layer3[layer_index] = layer3_switch[layer_index * self.l3_bitmapsize:layer_index * self.l3_bitmapsize + self.l3_bitmapsize]

        layer4 = {}
        layer4_switch = self.layer4_merge
        layer_index = l1_hash % self.size4
        layer4[layer_index] = layer4_switch[layer_index * self.l4_bitmapsize:layer_index * self.l4_bitmapsize + self.l4_bitmapsize]

        layer5 = {}
        layer5_switch = self.layer5_merge
        layer_index = l1_hash % self.size5
        layer5[layer_index] = layer5_switch[layer_index * self.l5_bitmapsize:layer_index * self.l5_bitmapsize + self.l5_bitmapsize]

        l1_count_0 = self.l1_bitmapsize - layer1[l1_hash % self.size1].count(1)
        l2_count_0 = self.l2_bitmapsize - layer2[l1_hash % self.size2].count(1)
        l3_count_0 = self.l3_bitmapsize - layer3[l1_hash % self.size3].count(1)
        l4_count_0 = self.l4_bitmapsize - layer4[l1_hash % self.size4].count(1)
        l5_count_0 = self.l5_bitmapsize - layer5[l1_hash % self.size5].count(1)

        l1_est = lc(l1_count_0, self.l1_bitmapsize)
        l2_est = lc(l2_count_0, self.l2_bitmapsize)
        l3_est = lc(l3_count_0, self.l3_bitmapsize)
        l4_est = lc(l4_count_0, self.l4_bitmapsize)
        l5_est = lc(l5_count_0, self.l5_bitmapsize)

        est1 = l1_est + l2_est + l3_est + l4_est + l5_est
        est2 = max(l1_est * 65536 / (65536 - self.sample1), 1)
        est_layer1 = est2

        est1 = l2_est + l3_est + l4_est + l5_est
        est2 = l2_est * 65536 / (65536 - self.sample2) * (65536 / self.sample1)
        est1 *= (65536 / self.sample1)
        est_layer2 = est2

        est1 = l3_est + l4_est + l5_est
        est2 = l3_est * 65536 / (65536 - self.sample3) * (65536 / self.sample2)
        est1 *= (65536 / self.sample2)
        est_layer3 = est2

        est1 = l4_est + l5_est
        est2 = l4_est * 65536 / (65536 - self.sample4) * (65536 / self.sample3)
        est1 *= (65536 / self.sample3)
        est_layer4 = est2

        layer = 0
        if l1_count_0 > self.l1_bitmapsize / 5:
            Est = est_layer1
            layer = 1
        elif l2_count_0 > self.l2_bitmapsize / 5:
            Est = max(est_layer1, est_layer2)
            layer = 2
        elif l3_count_0 > self.l3_bitmapsize / 5:
            Est = max(est_layer2, est_layer3)
            layer = 3
        elif l4_count_0 > self.l4_bitmapsize / 5:
            Est = max(est_layer3, est_layer4)
            layer = 4
        else:
            Est = max(l5_est * (65536 / self.sample4), est_layer4)
            layer = 5
        return (Est, layer)

    def query(self):
        self.ml_csv = "cvfdt_metrics.csv"
        if not os.path.exists(self.ml_csv):
            with open(self.ml_csv, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow([
                    "epoch_ts",
                    "ip",
                    "role",
                    "cm_count",
                    "delta_c",
                    "lemon_est",
                    "entropy",
                    "delta_lemon",
                    "dp_pred",
                    "cp_pred",
                    "traffic_label",
                    "victim_label",
                    "traffic_dp_result",
                    "traffic_cp_result",
                    "victim_dp_result",
                    "victim_cp_result"
                    ])
        # --- epoch-level state (this makes TN/FN possible when nothing is detected)
        epoch_ts = int(time.time())
        # --- buffers for per-epoch CSV writes (performance)
        ml_rows_buffer = []
        det_rows_buffer = []
        rows_logged = 0
        saw_gt_victim = False
        dp_epoch_digests = 0  # how many DP->CP events happened this epoch (based on threshold)
        cp_epoch_alert = 0    # did CP predict attack for any logged row in this epoch?

        # --- CP Option-3 per-epoch counts (only for rows that reach CP)
        cp_tr = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
        cp_v  = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

        for hh_id, l1_hash in self.hh_hash.items():

            if hh_id not in self.hh_dip:
                continue  # extra guard, very cheap
            ip = int_to_ip(self.hh_dip[hh_id])            
            l1_hash = self.hh_hash[hh_id]

            layer1 = {}
            layer1_switch = self.layer1_merge
            layer_index = l1_hash % self.size1
            layer1[layer_index] = layer1_switch[layer_index * self.l1_bitmapsize:layer_index * self.l1_bitmapsize + self.l1_bitmapsize]

            layer2 = {}
            layer2_switch = self.layer2_merge
            layer_index = l1_hash % self.size2
            layer2[layer_index] = layer2_switch[layer_index * self.l2_bitmapsize:layer_index * self.l2_bitmapsize + self.l2_bitmapsize]

            layer3 = {}
            layer3_switch = self.layer3_merge
            layer_index = l1_hash % self.size3
            layer3[layer_index] = layer3_switch[layer_index * self.l3_bitmapsize:layer_index * self.l3_bitmapsize + self.l3_bitmapsize]

            layer4 = {}
            layer4_switch = self.layer4_merge
            layer_index = l1_hash % self.size4
            layer4[layer_index] = layer4_switch[layer_index * self.l4_bitmapsize:layer_index * self.l4_bitmapsize + self.l4_bitmapsize]

            layer5 = {}
            layer5_switch = self.layer5_merge
            layer_index = l1_hash % self.size5
            layer5[layer_index] = layer5_switch[layer_index * self.l5_bitmapsize:layer_index * self.l5_bitmapsize + self.l5_bitmapsize]

            l1_count_0 = self.l1_bitmapsize - layer1[l1_hash % self.size1].count(1)
            l2_count_0 = self.l2_bitmapsize - layer2[l1_hash % self.size2].count(1)
            l3_count_0 = self.l3_bitmapsize - layer3[l1_hash % self.size3].count(1)
            l4_count_0 = self.l4_bitmapsize - layer4[l1_hash % self.size4].count(1)
            l5_count_0 = self.l5_bitmapsize - layer5[l1_hash % self.size5].count(1)

            l1_est = lc(l1_count_0, self.l1_bitmapsize)
            l2_est = lc(l2_count_0, self.l2_bitmapsize)
            l3_est = lc(l3_count_0, self.l3_bitmapsize)
            l4_est = lc(l4_count_0, self.l4_bitmapsize)
            l5_est = lc(l5_count_0, self.l5_bitmapsize)

            est_layer1 = l1_est * 65536 / (65536 - self.sample1)
            est_layer2 = l2_est * 65536 / (self.sample1 - self.sample2)
            est_layer3 = l3_est * 65536 / (self.sample2 - self.sample3)
            est_layer4 = l4_est * 65536 / (self.sample3 - self.sample4)
            est_layer5 = l5_est * 65536 / self.sample4

            # FAST CP ESTIMATION (NO ELIMINATION LOOPS)
            if l1_count_0 > self.l1_bitmapsize / 5:
                Est = est_layer1
            elif l2_count_0 > self.l2_bitmapsize / 5:
                Est = est_layer2
            elif l3_count_0 > self.l3_bitmapsize / 5:
                Est = est_layer3
            elif l4_count_0 > self.l4_bitmapsize / 5:
                Est = est_layer4
            else:
                Est = est_layer5


           # c = max(self.counter[p4sw][l1_hash % self.size1] for p4sw in self.counter) if self.counter else 0
           # if (c < 1000):
           #     continue
           # self.dp_to_cp_events += 1
           # dp_epoch_digests += 1
            c = max(self.counter[p4sw][l1_hash % self.size1] for p4sw in self.counter) if self.counter else 0

            # ---- NEW: per-epoch delta (FIX) ----
            """prev_c = self.hh_count.get(hh_id, 0)
            delta_c = c - prev_c
            self.hh_count[hh_id] = c
            logging.debug(
                f"[DP_CHECK] ip={int_to_ip(self.hh_dip[hh_id])} "
                f"c={c} prev_c={prev_c} delta_c={delta_c}"
            )
            """

            if c < DP_THRESHOLD:
                continue
            delta_c = c

            self.dp_to_cp_events += 1
            dp_epoch_digests += 1

            ip = int_to_ip(self.hh_dip[hh_id])

            # ===== OPTION 3: role-aware evaluation =====
            role = "victim" if ip == GT_VICTIM else "attacker"
            traffic_label = 1   # attack traffic exists (DP threshold passed)
            victim_label = 1 if ip == GT_VICTIM else 0

            print(f"{ip},{c},{Est}")

           
            logging.debug(f"DETECT {ip},{c},{Est}")
            det_rows_buffer.append([epoch_ts, ip, int(c), float(Est)])
# ================= CVFDT INTEGRATION START =================

            prev = getattr(self, "prev_lemon", {})
            last_est = float(prev.get(ip, Est))
            delta_lemon = float(Est) - last_est
            prev[ip] = float(Est)
            self.prev_lemon = prev

            entropy_val = self.last_entropy

            features = lemon_to_cic_features(
                cm_count=int(c),
                lemon_est=float(Est),
                delta_lemon=delta_lemon,
                entropy=entropy_val
            )

            y_pred = cvfdt.predict_one(features)
            # ---------------- DP decision ----------------
            dp_pred = 1 if c >= DP_THRESHOLD else 0

            # ---------------- CP decision ----------------
            cp_pred = int(y_pred) if y_pred is not None else 0
            cp_epoch_alert = 1 if cp_pred == 1 else cp_epoch_alert
            saw_gt_victim = True if ip == GT_VICTIM else saw_gt_victim
            rows_logged += 1

            # ---------------- Confusion ----------------
            # ===== OPTION 3 confusion matrices =====
            traffic_dp_result = confusion(dp_pred, traffic_label)
            traffic_cp_result = confusion(cp_pred, traffic_label)

            victim_dp_result  = confusion(dp_pred, victim_label)
            victim_cp_result  = confusion(cp_pred, victim_label)

            # accumulate CP-only confusion matrices (Option-3)
            cp_tr[traffic_cp_result] += 1
            cp_v[victim_cp_result] += 1


            #cvfdt.learn_one(features, label)
            ml_rows_buffer.append([
                epoch_ts,
                ip,
                role,
                int(c),
                delta_c,
                float(Est),
                float(entropy_val),
                float(delta_lemon),
                dp_pred,
                cp_pred,
                traffic_label,
                victim_label,
                traffic_dp_result,
                traffic_cp_result,
                victim_dp_result,
                victim_cp_result
            ])
            #logging.debug(f"[CVFDT] pred={y_pred}, features={features}")
            #logging.debug(f"[STATS] DP?CP events so far: {self.dp_to_cp_events}")
 
            # ================= CVFDT INTEGRATION END =================

        # --- flush buffered CSV writes (once per epoch)
        if det_rows_buffer:
            with open(self.out_csv, "a", newline="") as f:
                w = csv.writer(f)
                w.writerows(det_rows_buffer)

        if ml_rows_buffer:
            with open(self.ml_csv, "a", newline="") as f:
                w = csv.writer(f)
                w.writerows(ml_rows_buffer)


        # --- CP Option-3 epoch summary (only based on rows that reached CP this epoch)
        # Add to running totals
        for k in ("TP","TN","FP","FN"):
            self.cm_cp_traffic[k] += cp_tr[k]
            self.cm_cp_victim[k]  += cp_v[k]

        with open(self.cp_epoch_csv, "a", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                epoch_ts,
                cp_tr["TP"], cp_tr["TN"], cp_tr["FP"], cp_tr["FN"],
                cp_v["TP"],  cp_v["TN"],  cp_v["FP"],  cp_v["FN"],
                rows_logged
            ])

        #logging.info(f"[CM_CP_TRAFFIC] TP={self.cm_cp_traffic['TP']} TN={self.cm_cp_traffic['TN']} FP={self.cm_cp_traffic['FP']} FN={self.cm_cp_traffic['FN']}")
        #logging.info(f"[CM_CP_VICTIM]  TP={self.cm_cp_victim['TP']} TN={self.cm_cp_victim['TN']} FP={self.cm_cp_victim['FP']} FN={self.cm_cp_victim['FN']}")

# --- epoch-level summary + confusion matrices (includes 'no alert')
        epoch_label = 1 if saw_gt_victim else 0
        dp_alert = 1 if dp_epoch_digests > 0 else 0
        cp_alert = 1 if cp_epoch_alert > 0 else 0

        dp_cm_key = confusion(dp_alert, epoch_label)
        self.cm_dp[dp_cm_key] += 1

        if dp_alert == 1:
            cp_cm_key = confusion(cp_alert, epoch_label)
            self.cm_cp[cp_cm_key] += 1

        with open(self.epoch_csv, "a", newline="") as f:
            w = csv.writer(f)
            w.writerow([epoch_ts, epoch_label, dp_alert, cp_alert, dp_epoch_digests, rows_logged])

        #logging.info(f"[EPOCH] ts={epoch_ts} label={epoch_label} dp_alert={dp_alert} cp_alert={cp_alert} dp_digests={dp_epoch_digests} rows={rows_logged}")
        logging.info(f"[CM_DP_TOTAL] TP={self.cm_dp['TP']} TN={self.cm_dp['TN']} FP={self.cm_dp['FP']} FN={self.cm_dp['FN']}")
        logging.info(f"[CM_CP_TOTAL] TP={self.cm_cp['TP']} TN={self.cm_cp['TN']} FP={self.cm_cp['FP']} FN={self.cm_cp['FN']}")
        self.dp_epoch_digests = dp_epoch_digests

    def entropy(self):
        epy_map = []
        for slot in range(0, self.size1):
            l1_hash = slot
            l1_bitmap = self.layer1_merge[slot * self.l1_bitmapsize:slot * self.l1_bitmapsize + self.l1_bitmapsize]
            l1_count_0 = self.l1_bitmapsize - sum(l1_bitmap)
            if l1_count_0 > self.l1_bitmapsize * 0.8:
                epy_map.append(lc(l1_count_0, self.l1_bitmapsize))
                continue

            l2_hash = slot % self.size2
            l2_bitmap = self.layer2_merge[l2_hash * self.l2_bitmapsize:l2_hash * self.l2_bitmapsize + self.l2_bitmapsize]
            l2_count_0 = self.l2_bitmapsize - sum(l2_bitmap)
            if l2_count_0 > self.l2_bitmapsize * 0.2:
                l2_est = lc(l2_count_0, self.l2_bitmapsize) * 65536 / (65536 - self.sample2) * (65536 / self.sample1)
                epy_map.append(l2_est)
                continue

            l3_hash = slot % self.size3
            l3_bitmap = self.layer3_merge[l3_hash * self.l3_bitmapsize:l3_hash * self.l3_bitmapsize + self.l3_bitmapsize]
            l3_count_0 = self.l3_bitmapsize - sum(l3_bitmap)
            if l3_count_0 > self.l3_bitmapsize * 0.2:
                l3_est = lc(l3_count_0, self.l3_bitmapsize) * 65536 / (65536 - self.sample3) * (65536 / self.sample2)
                epy_map.append(l3_est)
                continue

            l4_hash = slot % self.size4
            l4_bitmap = self.layer4_merge[l4_hash * self.l4_bitmapsize:l4_hash * self.l4_bitmapsize + self.l4_bitmapsize]
            l4_count_0 = self.l4_bitmapsize - sum(l4_bitmap)
            if l4_count_0 > self.l4_bitmapsize * 0.2:
                l4_est = lc(l4_count_0, self.l4_bitmapsize) * 65536 / (65536 - self.sample4) * (65536 / self.sample3)
                epy_map.append(l4_est)
                continue

            l5_hash = slot % self.size5
            l5_bitmap = self.layer5_merge[l5_hash * self.l5_bitmapsize:l5_hash * self.l5_bitmapsize + self.l5_bitmapsize]
            l5_count_0 = self.l5_bitmapsize - sum(l5_bitmap)
            l5_est = lc(l5_count_0, self.l5_bitmapsize) * (65536 / self.sample4)
            epy_map.append(l5_est)

        entropy = epy(epy_map, self.size1)
        self.last_entropy = entropy
        logging.info('entropy_src: %f', entropy)

    def heavyhitter_only(self):
        self.hh_dip = {}
        for p4switch in self.topo.get_p4switches():
            if (len(p4switch) == 4):
                continue
            if (len(p4switch) > 4):
                continue
            print(1)
            heavy_dip = self.controllers[p4switch].register_read("lemon_heavy_id")
            heavy_hash = self.controllers[p4switch].register_read("lemon_heavy_tag")
            self.layer1[p4switch] = self.controllers[p4switch].register_read("lemon_layer1")
            #self.layer2[p4switch] = self.controllers[p4switch].register_read("lemon_layer2")
            #self.layer3[p4switch] = self.controllers[p4switch].register_read("lemon_layer3")
            #self.layer4[p4switch] = self.controllers[p4switch].register_read("lemon_layer4")
            #self.layer5[p4switch] = self.controllers[p4switch].register_read("lemon_layer5")
            self.counter[p4switch] = self.controllers[p4switch].register_read("counter")

            for slot in range(0, self.heavysize):
                if heavy_dip[slot] != 0:
                    self.hh_dip[slot] = heavy_dip[slot]
                    self.hh_hash[slot] = heavy_hash[slot]

        """for hh_id in range(0, self.heavysize):
            if hh_id not in self.hh_dip.keys():
                continue
            l1_hash = self.hh_hash[hh_id]
        """
        for hh_id, (dip, l1_hash) in self.hh_dip.items():
            l1_hash = self.hh_hash[hh_id]

            c = max(self.counter[p4sw][l1_hash % self.size1] for p4sw in self.counter) if self.counter else 0
            if (c < 1000):
                continue

            print(l1_hash)

            layer1 = {}
            for layer1_swh in self.layer1.keys():
                layer1_switch = self.layer1[layer1_swh]
                layer_index = l1_hash % self.size1
                if layer_index in layer1.keys():
                    list1 = layer1[layer_index]
                    list2 = layer1_switch[layer_index * self.l1_bitmapsize:layer_index * self.l1_bitmapsize + self.l1_bitmapsize]
                    layer1[layer_index] = [a | b for a, b in zip(list1, list2)]
                else:
                    layer1[layer_index] = layer1_switch[layer_index * self.l1_bitmapsize:layer_index * self.l1_bitmapsize + self.l1_bitmapsize]

            layer2 = {}
            for layer2_name in self.layer2.keys():
                layer2_switch = self.layer2[layer2_name]
                layer_index = l1_hash % self.size2
                if layer_index in layer2.keys():
                    list1 = layer2[layer_index]
                    list2 = layer2_switch[layer_index * self.l2_bitmapsize:layer_index * self.l2_bitmapsize + self.l2_bitmapsize]
                    layer2[layer_index] = [a | b for a, b in zip(list1, list2)]
                else:
                    layer2[layer_index] = layer2_switch[layer_index * self.l2_bitmapsize:layer_index * self.l2_bitmapsize + self.l2_bitmapsize]

            layer3 = {}
            for layer3_name in self.layer3.keys():
                layer3_switch = self.layer3[layer3_name]
                layer_index = l1_hash % self.size3
                if layer_index in layer3.keys():
                    list1 = layer3[layer_index]
                    list2 = layer3_switch[layer_index * self.l3_bitmapsize:layer_index * self.l3_bitmapsize + self.l3_bitmapsize]
                    layer3[layer_index] = [a | b for a, b in zip(list1, list2)]
                else:
                    layer3[layer_index] = layer3_switch[layer_index * self.l3_bitmapsize:layer_index * self.l3_bitmapsize + self.l3_bitmapsize]

            layer4 = {}
            for layer4_name in self.layer4.keys():
                layer4_switch = self.layer4[layer4_name]
                layer_index = l1_hash % self.size4
                if layer_index in layer4.keys():
                    list1 = layer4[layer_index]
                    list2 = layer4_switch[layer_index * self.l4_bitmapsize:layer_index * self.l4_bitmapsize + self.l4_bitmapsize]
                    layer4[layer_index] = [a | b for a, b in zip(list1, list2)]
                else:
                    layer4[layer_index] = layer4_switch[layer_index * self.l4_bitmapsize:layer_index * self.l4_bitmapsize + self.l4_bitmapsize]

            layer5 = {}
            for layer5_name in self.layer5.keys():
                layer5_switch = self.layer5[layer5_name]
                layer_index = l1_hash % self.size5
                if layer_index in layer5.keys():
                    list1 = layer5[layer_index]
                    list2 = layer5_switch[layer_index * self.l5_bitmapsize:layer_index * self.l5_bitmapsize + self.l5_bitmapsize]
                    layer5[layer_index] = [a | b for a, b in zip(list1, list2)]
                else:
                    layer5[layer_index] = layer5_switch[layer_index * self.l5_bitmapsize:layer_index * self.l5_bitmapsize + self.l5_bitmapsize]

            l1_count_0 = self.l1_bitmapsize - layer1[l1_hash % self.size1].count(1)
            l2_count_0 = self.l2_bitmapsize - layer2[l1_hash % self.size2].count(1)
            l3_count_0 = self.l3_bitmapsize - layer3[l1_hash % self.size3].count(1)
            l4_count_0 = self.l4_bitmapsize - layer4[l1_hash % self.size4].count(1)
            l5_count_0 = self.l5_bitmapsize - layer5[l1_hash % self.size5].count(1)

            l1_est = lc(l1_count_0, self.l1_bitmapsize)
            l2_est = lc(l2_count_0, self.l2_bitmapsize)
            l3_est = lc(l3_count_0, self.l3_bitmapsize)
            l4_est = lc(l4_count_0, self.l4_bitmapsize)
            l5_est = lc(l5_count_0, self.l5_bitmapsize)

            est1 = l1_est + l2_est + l3_est + l4_est + l5_est
            est2 = max(l1_est * 65536 / (65536 - self.sample1), 1)
            est_layer1 = min(est1, est2)

            est1 = l2_est + l3_est + l4_est + l5_est
            est2 = l2_est * 65536 / (65536 - self.sample2) * (65536 / self.sample1)
            est1 *= (65536 / self.sample1)
            est_layer2 = min(est1, est2)

            est1 = l3_est + l4_est + l5_est
            est2 = l3_est * 65536 / (65536 - self.sample3) * (65536 / self.sample2)
            est1 *= (65536 / self.sample2)
            est_layer3 = min(est1, est2)

            est1 = l4_est + l5_est
            est2 = l4_est * 65536 / (65536 - self.sample4) * (65536 / self.sample3)
            est1 *= (65536 / self.sample3)
            est_layer4 = min(est1, est2)

            if l1_count_0 > self.l1_bitmapsize / 5:
                Est = est_layer1
            elif l2_count_0 > self.l2_bitmapsize / 5:
                Est = max(est_layer1, est_layer2)
            elif l3_count_0 > self.l3_bitmapsize / 5:
                Est = max(est_layer2, est_layer3)
            elif l4_count_0 > self.l4_bitmapsize / 5:
                Est = max(est_layer3, est_layer4)
            else:
                Est = max(l5_est * (65536 / self.sample4), est_layer4)

            c = max(self.counter[p4sw][l1_hash % self.size1] for p4sw in self.counter) if self.counter else 0
            if (c < 1000):
                continue
            ip = int_to_ip(self.hh_dip[hh_id])

            # ===== OPTION 3: role-aware evaluation =====
            role = "victim" if ip == GT_VICTIM else "attacker"
            traffic_label = 1   # attack traffic exists (DP threshold passed)
            victim_label = 1 if ip == GT_VICTIM else 0

            print(f"{ip},{c},{Est}")
            logging.info(f"{ip},{c},{Est}")

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            print("p4switch:", p4switch, "thrift_port:", thrift_port)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)
            if (len(p4switch) >= 4):
                continue

    def test(self):  # for timeing and change T
        self.counter_query(20)


if __name__ == "__main__":
    
    # -------------------------------
    # Experiment timeline
    # -------------------------------
    controller = myController()
 
    logging.info('start')
    EPOCH_LEN = 1 # seconds
    try:
        while True:
            t0 = time.time()
            controller.collect_merge()
            # compute entropy less frequently to reduce epoch processing time
            if controller.dp_epoch_digests > 0 and controller._epoch_counter % controller.entropy_every == 0:
                controller.entropy()
            controller.query()
            controller._epoch_counter += 1
            dp_time = time.time() - t0
            sleep_time = max(0.0, EPOCH_LEN - dp_time)
            time.sleep(sleep_time)
            logging.info(f"[TIME] DP epoch processing time: {dp_time:.6f} sec")
# controller.heavyhitter_only()  # optional
    except KeyboardInterrupt:
        print("\n[Controller] Stopped by user")
