#coding:utf-8
# === Controller with Option-3 (role-aware evaluation) safely merged ===
# Existing logic preserved, minimal fixes + additions only

import time, logging, csv, os, math, pickle
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI

DP_THRESHOLD = 1000
GT_VICTIM = "9.9.9.9"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.normpath(os.path.join(BASE_DIR, "..", "ml_model", "cvfdt_cp_model.pkl"))

with open(MODEL_PATH, "rb") as f:
    cvfdt = pickle.load(f)

def confusion(pred, label):
    if pred == 1 and label == 1: return "TP"
    if pred == 1 and label == 0: return "FP"
    if pred == 0 and label == 1: return "FN"
    return "TN"

def int_to_ip(num):
    return ".".join(str((num >> (8*i)) & 0xFF) for i in [3,2,1,0])

class myController:
    def __init__(self):
        self.topo = load_topo("/home/devar/Lemon/lemon_bmv2/topology.json")
        self.controllers = {}
        self.hh_dip, self.hh_hash = {}, {}
        self.counter = {}
        self.size1 = 524288
        self.heavysize = 8192
        self.prev_lemon = {}
        self.last_entropy = 0.0

        self.csv = "cvfdt_metrics.csv"
        if not os.path.exists(self.csv):
            with open(self.csv,"w",newline="") as f:
                csv.writer(f).writerow([
                    "epoch","ip","role","count",
                    "dp_pred","cp_pred",
                    "traffic_label","victim_label",
                    "traffic_dp","traffic_cp",
                    "victim_dp","victim_cp"
                ])

        for sw in self.topo.get_p4switches():
            self.controllers[sw] = SimpleSwitchThriftAPI(self.topo.get_thrift_port(sw))

    def collect_merge(self):
        self.hh_dip.clear()
        for sw in self.controllers:
            self.counter[sw] = self.controllers[sw].register_read("counter")
            hid = self.controllers[sw].register_read("lemon_heavy_id")
            htag = self.controllers[sw].register_read("lemon_heavy_tag")
            for i in range(self.heavysize):
                if hid[i] != 0:
                    self.hh_dip[i] = hid[i]
                    self.hh_hash[i] = htag[i]

    def query(self):
        epoch = int(time.time())
        for i in self.hh_dip:
            h = self.hh_hash[i]
            c = max(self.counter[sw][h % self.size1] for sw in self.counter)
            if c < DP_THRESHOLD:
                continue

            ip = int_to_ip(self.hh_dip[i])
            role = "victim" if ip == GT_VICTIM else "attacker"

            dp_pred = 1
            cp_pred = int(cvfdt.predict_one({"cm_count":c,"lemon_est":c,"delta_lemon":0,"entropy":self.last_entropy}) or 0)

            traffic_label = 1
            victim_label = 1 if ip == GT_VICTIM else 0

            with open(self.csv,"a",newline="") as f:
                csv.writer(f).writerow([
                    epoch, ip, role, c,
                    dp_pred, cp_pred,
                    traffic_label, victim_label,
                    confusion(dp_pred,traffic_label),
                    confusion(cp_pred,traffic_label),
                    confusion(dp_pred,victim_label),
                    confusion(cp_pred,victim_label)
                ])

            logging.info(f"[DETECT] {ip} role={role} c={c}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    c = myController()
    while True:
        t0=time.time()
        c.collect_merge()
        c.query()
        time.sleep(3)
        logging.info(f"[TIME] epoch {time.time()-t0:.2f}s")
