# Hybrid Epoch-Based DDoS Detection in SDN (BMv2 + P4)

## Overview

This project implements a **hybrid flow-based DDoS detection framework for Software-Defined Networks (SDN)** using **programmable data planes (P4/BMv2)** and **control-plane machine learning**.

The system combines:
- **Lightweight, routing-oblivious sketch-based monitoring in the data plane**, provided by Lemon  
- **Adaptive machine-learning-based classification in the control plane**

The objective is to achieve **early attack detection**, **low data-plane overhead**, and **high detection accuracy**, while remaining scalable.

---

## Project Structure

```
.
├── bmv2/
│   ├── measurement.p4           # Data-plane sketch implementation
│   ├── divider.p4               # Simple switch for packet injection
│   ├── p4app.json               # Network configuration
│   ├── s1-commands.txt          # Hash and sketch configuration
│   ├── baselines/               # Baseline P4 implementations
│   └── topologies/              # Network topologies
│
├── controlplane/
│   ├── controller/
│   │   └── deva_controller.py   # Control-plane logic and ML inference
│   ├── pkt_send/                # Packet sending scripts
│   └── evaluation/              # Evaluation and metric scripts
│
├── datasets/
│   └── (downloaded via script)  # Kaggle-hosted dataset
│
├── dataset.sh                   # Kaggle dataset download script
│
└── README.md
```

---

## System Requirements

- protobuf v3.18.1  
- grpc v1.43.2  
- PI (P4Runtime) v0.1.0  
- p4c v1.2.2.1  
- BMv2 v1.15.0  
- Mininet (latest)  
- p4-utils (latest)  
- Python 3.8+

---
## Python Environment

- Python version: **3.10**
- A virtual environment is recommended but not included in this repository.

### Setup

```bash
python3.10 -m venv lemon-venv
source venv/bin/activate
pip install -r requirements.txt
```

## Dataset

The dataset used in this project is **publicly available on Kaggle** and curated by the author.

**Kaggle Dataset:**  
https://www.kaggle.com/datasets/devanandsrinivasan/mwai-5k

### Dataset Description

- Benign and DDoS attack PCAP files  
- Traffic derived from **CIC-IDS-2017 (Friday)**  
- Organised for SDN-based flow-level DDoS experiments  

The dataset is **not stored in this repository** to keep it lightweight.

---

## Downloading the Dataset

The dataset can be downloaded automatically using the provided script.

### Prerequisites
- Kaggle account  
- Kaggle API key (`kaggle.json`)

### Steps

```bash
chmod +x dataset.sh
./dataset.sh
```

The script downloads and extracts the dataset into the `datasets/` directory.

---

## Running the System

### 1. Start the BMv2 Network

```bash
cd bmv2
sudo p4run
```

If successful, the Mininet CLI will appear:

```
*** Starting CLI:
mininet>
```

---

### 2. Packet Injection

**Method 1: Divider Switch**

Packets can be injected using `divider.p4`.  
Ensure `divider.p4` is included in `p4app.json` and connected to all measurement points.

**Method 2: Control-Plane Packet Sender (Recommended)**

```bash
sudo python3 controlplane/pkt_send/pkg_sending.py
```

This method provides better control over traffic patterns and attack scenarios.

---

### 3. Start the Control Plane

```bash
sudo python3 controlplane/controller/deva_controller.py
```

Successful startup prints switch connection details:

```
p4switch: s01 thrift_port: 9090
p4switch: s02 thrift_port: 9091
...
```

---

## Control-Plane Functions

```python
controller.collect_merge()   # Collect sketch data from all switches
controller.query()           # Detect high-volume (suspected attack) flows
controller.entropy()         # Entropy-based traffic estimation
```

---

## Flow Key Configuration

Flow and packet keys can be configured in `measurement.p4` using bit masks.

### Flow-Level Monitoring

```p4
bit<32> sip_mask_f = 0;
bit<32> dip_mask_f = 0xffffffff;
bit<16> sport_mask_f = 0;
bit<16> dport_mask_f = 0;
bit<8>  protocol_mask_f = 0;
```

### Packet-Level Hashing

```p4
bit<32> sip_mask = 0xffffffff;
bit<32> dip_mask = 0xffffffff;
bit<16> sport_mask = 0xffff;
bit<16> dport_mask = 0xffff;
bit<8>  protocol_mask = 0xff;
```

---

## Baselines and Topologies

Baseline implementations and alternative network topologies are provided in:

- `baselines/`
- `topologies/`

To evaluate different setups, replace:

- `measurement.p4`
- `p4app.json`

with the corresponding files.

---

## Reproducibility

- All experiments are reproducible  
- Dataset is publicly available  
- No large files stored in the repository  
- Scripts automate setup and evaluation  

---

## Project Context

This project was developed as part of an **Personal research project** and is intended for **academic and experimental use **.

The original Lemon framework that inspired the data-plane design is available at:  
https://github.com/f-555/Lemon

---

## Contact

**Devanand Srinivasan**  
MSc Cybersecurity  
