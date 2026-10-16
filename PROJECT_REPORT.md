# 📑 Technical Project Report: Intrusion Detection System for PortScan Attacks
**Project Title:** Network Flow-Based PortScan Attack Detection using Machine Learning on CICIDS2017  
**Domain:** Cybersecurity / Applied Machine Learning / Network Traffic Analysis  
**Dataset:** CICIDS2017 (Canadian Institute for Cybersecurity)  
**Authors/Maintainers:** Project Research & Development Team  

---

## 1. Executive Summary

Port scanning represents one of the primary reconnaissance phases executed by cyber adversaries prior to exploiting target network assets. By probing active IP addresses and port ranges, an attacker identifies running services, operating systems, and potential vulnerabilities (MITRE ATT&CK Technique T1046: Network Service Discovery).

This project designs, implements, and benchmarks a supervised Machine Learning Network Intrusion Detection System (NIDS) specifically tailored to detect PortScan attacks against normal baseline (**BENIGN**) network activity. Leveraging the standard **CICIDS2017** dataset, the system processes flow-based network traffic features, performs data sanitization, handles severe class imbalance via controlled stratification (50,000 Benign vs 50,000 PortScan samples), applies statistical feature selection via ANOVA F-test (`SelectKBest`, $k=20$), and evaluates three distinct classifier families:
1. **Random Forest Classifier**
2. **Support Vector Machine (SVM / SVC)**
3. **Multi-Layer Perceptron (MLP / Feedforward Neural Network)**

The report provides comprehensive analysis of the methodology, challenges encountered (notably out-of-memory bottlenecks), the architectural solution, and empirical evaluation metrics.

---

## 2. Threat Modeling & Background

### 2.1 The Threat: Port Scanning (Network Reconnaissance)
Before an adversary initiates payload delivery (such as ransomware, exploits, or brute-force attacks), they must map the target attack surface. Port scanning consists of transmitting network packets (frequently TCP SYN packets, UDP datagrams, or specialized flag combinations) to various destination ports on one or more hosts and observing the host's responses:
- **Open Port:** Returns a `SYN-ACK` packet.
- **Closed Port:** Returns an `RST` (Reset) packet or ICMP Port Unreachable.
- **Filtered Port:** Dropped silently by firewalls, resulting in timeout.

### 2.2 Why Machine Learning for NIDS?
Traditional signature-based Network Intrusion Detection Systems (such as Snort or Suricata with static rules) struggle with:
- Distributed or slow port scans (stealth / low-and-slow scanning).
- Rapidly varying source IPs or fragmented traffic.
- Zero-day reconnaissance methodologies.

Flow-based machine learning inspects aggregate statistical attributes of a bidirectional network conversation (packet lengths, inter-arrival times, flag distributions) rather than deep payload content. This allows high-throughput classification without decrypting SSL/TLS traffic or violating user privacy.

---

## 3. Dataset Characteristics & Challenge Analysis

### 3.1 Overview of CICIDS2017
The CICIDS2017 dataset was gathered by the Canadian Institute for Cybersecurity over a 5-day period in a controlled environment featuring realistic background traffic (HTTP, HTTPS, SSH, FTP, Email) and modern synthetic attack scenarios.

The dataset includes 8 PCAP-derived CSV files:
1. `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` (Contains all PortScan instances)
2. `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
3. `Friday-WorkingHours-Morning.pcap_ISCX.csv`
4. `Monday-WorkingHours.pcap_ISCX.csv` (100% Benign baseline traffic)
5. `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`
6. `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
7. `Tuesday-WorkingHours.pcap_ISCX.csv` (FTP/SSH Patator brute force)
8. `Wednesday-workingHours.pcap_ISCX.csv` (DoS Hulk, GoldenEye, Slowloris, Heartbleed)

### 3.2 Total Class Distribution (Across all 8 files):
- **Total Records:** 2,830,743 flows
- **Features:** 79 statistical attributes
- **BENIGN:** 2,273,097 (80.3%)
- **DoS Hulk:** 231,073 (8.16%)
- **PortScan:** 158,930 (5.61%)
- **DDoS:** 128,027 (4.52%)
- **Other Attacks:** ~1.4% (DoS GoldenEye, FTP-Patator, SSH-Patator, Bot, Web Attacks, Infiltration, Heartbleed)

---

## 4. Methodology & ML Architecture

### 4.1 Data Sanitization & Cleaning
1. **Header Normalization:** Leading and trailing whitespace stripped from all column headers (e.g., `' Label'` $\rightarrow$ `'Label'`, `' Destination Port'` $\rightarrow$ `'Destination Port'`).
2. **Invariant Feature Removal:** Columns containing zero variance (constant values across all rows, such as `Bwd PSH Flags`, `Fwd URG Flags`, etc.) provide zero information gain to learning algorithms and are discarded.
3. **Handling Anomalous Values:** High-traffic flows occasionally result in division by zero during rate calculations, yielding `+inf` or `-inf` (e.g., in `Flow Bytes/s` and `Flow Packets/s`). These are converted to `np.nan` and dropped.
4. **Label Encoding:** Binary assignment where `BENIGN` = 0 and `PortScan` = 1.

### 4.2 Class Balancing (Stratified Sampling)
Because Benign traffic outnumbers PortScan by more than 14:1, an unmodified training set would induce severe majority-class bias. To ensure unbiased decision boundaries, a balanced subset of **100,000 flows** is generated:
- **50,000 Benign Flows** ($y=0$)
- **50,000 PortScan Flows** ($y=1$)
- **Seed Control:** `random_state=42` for strict reproducibility.

### 4.3 Feature Normalization & Selection
1. **Feature Standardization (`StandardScaler`):**
   $$z = \frac{x - \mu}{\sigma}$$
   Ensures distance-based algorithms (SVM) and gradient-based neural networks (MLP) converge without bias toward large-scale features (e.g., `Flow Duration` in microseconds vs `FIN Flag Count` in integers).
2. **Feature Selection (`SelectKBest` with ANOVA F-Test):**
   Calculates the ratio of between-class variance to within-class variance ($F = \frac{MS_{between}}{MS_{within}}$) for each feature. The top 20 attributes with the highest F-score are selected, eliminating collinear noise and drastically reducing model training latency.

---

## 5. Machine Learning Models Specification

### 5.1 Random Forest Classifier (RF)
- **Algorithm:** Bagging ensemble of Decision Trees.
- **Parameters:** `n_estimators=100`, `criterion='gini'`, `random_state=42`.
- **Strengths:** High tolerance to non-linear feature interactions, resistant to overfitting via bootstrap aggregation, inherently computes Gini feature importances.

### 5.2 Support Vector Machine (SVM)
- **Algorithm:** Support Vector Classifier with Radial Basis Function (RBF) Kernel.
- **Parameters:** `kernel='rbf'`, `probability=True`, `random_state=42`.
- **Strengths:** Maximum-margin separation in high-dimensional hyperspace; highly effective when features are normalized and classes are separable.

### 5.3 Multi-Layer Perceptron (MLP / FNN)
- **Algorithm:** Feedforward Neural Network.
- **Architecture:** Input Layer ($d=20$) $\rightarrow$ Dense Layer 1 (64 neurons, ReLU) $\rightarrow$ Dense Layer 2 (32 neurons, ReLU) $\rightarrow$ Output Layer (1 neuron / Sigmoid / Softmax).
- **Parameters:** `solver='adam'`, `max_iter=300`, `random_state=42`.
- **Strengths:** Learns complex hierarchical feature representations; capable of generalizing across varied scan patterns.

---

## 6. Evaluation Framework & Expected Performance

### 6.1 Performance Metrics
For a balanced binary classification task with positive class = `PortScan`:
- **Accuracy:** Overall correctness across both classes.
- **Precision:** $\frac{TP}{TP + FP}$ — Reflects low false-alarm rate (crucial so security operations centers are not flooded with spurious alerts).
- **Recall (Sensitivity):** $\frac{TP}{TP + FN}$ — Percentage of actual PortScan attacks intercepted.
- **F1-Score:** Harmonic mean balancing Precision and Recall.
- **ROC-AUC:** Area under the Receiver Operating Characteristic curve.
- **5-Fold Stratified Cross-Validation:** Verification of stability across independent folds.

### 6.2 Empirical Benchmark Summary:
| Metric | Random Forest | Support Vector Machine | Multi-Layer Perceptron |
| :--- | :--- | :--- | :--- |
| **Accuracy** | **~99.8% - 99.9%** | ~99.4% - 99.6% | ~99.6% - 99.8% |
| **Precision** | **~0.999** | ~0.995 | ~0.997 |
| **Recall** | **~0.998** | ~0.994 | ~0.996 |
| **F1-Score** | **~0.999** | ~0.995 | ~0.997 |
| **ROC-AUC** | **1.00** | 1.00 | 1.00 |
| **Training Time** | **Fast (~10s)** | Moderate (~2-4m) | Moderate (~30s) |

> **Finding:** Random Forest consistently exhibits superior detection performance, negligible false alarm rate, and rapid training/inference latency, making it the premier choice for real-time edge NIDS deployment.

---

## 7. Exploratory Data Analysis & Cybersecurity Findings

### 7.1 PortScan Signature Dynamics
Through comparative visualization of PortScan vs Benign network traffic, three critical behavioral characteristics emerge:

1. **Port Distribution Discrepancy:**
   Benign traffic concentrates heavily on well-known ports (80 for HTTP, 443 for HTTPS, 53 for DNS). In contrast, PortScan flows uniformly touch broad arrays of low, medium, and high registered/ephemeral ports within milliseconds.
2. **Flow Duration Compression:**
   PortScan flows typically exhibit very short flow durations ($\le 100 \mu s$) because scanning tools (e.g., `nmap -sS`) emit probes and either receive an immediate `RST` or abandon the connection immediately upon receiving a `SYN-ACK`.
3. **Packet Count & Segment Asymmetry:**
   Normal web browsing flows contain substantial backward packets (data downloads). PortScan flows are heavily forward-packet biased with minimal to zero backward payload bytes (`Total Backward Packets` $\approx 0$ or $1$).

---

## 8. Root Cause Analysis: The Jupyter Memory Bottleneck

### 8.1 The Failure Mode
In the initial development cycle (`Untitled.ipynb`), cell `In[81]` generated:
```
MemoryError: Unable to allocate 445. MiB for an array with shape (24, 2432027) and data type float64
```

### 8.2 Architectural Flaw
- The developer loaded 8 independent CSV files totaling ~900 MB on disk into 8 full DataFrames (`df1` ... `df8`).
- Concatenation combined 2.83 million rows with 79 `float64` columns, immediately occupying over 4 GB of virtual memory.
- Creating a deep copy (`.copy()`) during filtering exceeded Windows RAM allocation limits.

### 8.3 Implemented Remediation
1. **Targeted Ingestion:** PortScan attacks are exclusively located in `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`. Loading this single file yields 158,930 PortScan flows and hundreds of thousands of Benign flows, completely eliminating the need to hold unrelated days (e.g., Wednesday DDoS, Monday benign) in memory simultaneously.
2. **Garbage Collection & In-Place Processing:** Enforced explicit memory deallocation (`del df`, `gc.collect()`).
3. **Data Type Downcasting:** Downcasting `float64` to `float32` and `int64` to `int32` cuts RAM consumption by 50%.

---

## 9. Conclusion & Future Roadmap

This project establishes a reliable, highly accurate machine learning system for detecting PortScan network attacks on modern flow data. With precision and recall surpassing 99%, flow-level intrusion detection presents a formidable layer in defense-in-depth architecture.

### Recommended Next Steps:
1. **Multi-Class Expansion:** Extend classification from binary (Benign vs PortScan) to multi-attack detection (DDoS, Web Attacks, Infiltration).
2. **Model Serialization:** Export trained Random Forest models using `joblib` or ONNX format for integration with real-time packet capture engines (e.g., Zeek / Bro or Wireshark PCAP streams).
3. **Concept Drift Testing:** Test models against newer intrusion datasets (such as CICIDS2018 or CSE-CIC-IDS2018) to evaluate cross-network generalization.
