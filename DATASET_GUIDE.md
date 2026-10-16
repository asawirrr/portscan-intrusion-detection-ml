# 📚 CICIDS2017 Dataset & Feature Dictionary Guide

The **CICIDS2017 (Canadian Institute for Cybersecurity Intrusion Detection System 2017)** dataset contains benign network traffic and up-to-date realistic cyber attacks. The raw packet capture data (PCAPs) was processed using **CICFlowMeter** to extract **79 statistical network flow features**.

This guide provides a comprehensive dictionary of all features, their cybersecurity meanings, and their relevance to intrusion detection.

---

## 🗂️ 1. Dataset Files & Attack Distribution

| File Name | Day / Time | Size on Disk | Primary Attack Vectors Contained |
| :--- | :--- | :--- | :--- |
| `Monday-WorkingHours.pcap_ISCX.csv` | Monday | 176 MB | **BENIGN** (Normal baseline traffic only) |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | Tuesday | 135 MB | **FTP-Patator, SSH-Patator** (Brute-force) |
| `Wednesday-workingHours.pcap_ISCX.csv` | Wednesday | 225 MB | **DoS Slowloris, Slowhttptest, Hulk, GoldenEye, Heartbleed** |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | Thursday (AM) | 52 MB | **Web Attacks (Brute Force, XSS, SQL Injection)** |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | Thursday (PM) | 83 MB | **Infiltration, Botnet activity** |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | Friday (AM) | 58 MB | **Botnet traffic** |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | Friday (PM) | 77 MB | **PortScan** (Network reconnaissance attacks) |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | Friday (PM) | 77 MB | **DDoS LOIC** (Distributed Denial of Service) |

---

## 📊 2. Overall Class Distribution

| Class Label | Number of Flows | Percentage (%) | Description |
| :--- | :--- | :--- | :--- |
| `BENIGN` | 2,273,097 | 80.30% | Normal, authorized network traffic |
| `DoS Hulk` | 231,073 | 8.16% | HTTP Unbearable Load King Denial of Service |
| `PortScan` | **158,930** | **5.61%** | **Target of this project (Reconnaissance)** |
| `DDoS` | 128,027 | 4.52% | Distributed Denial of Service |
| `DoS GoldenEye` | 10,293 | 0.36% | Application-layer Denial of Service |
| `FTP-Patator` | 7,938 | 0.28% | Multi-threaded FTP credential brute forcing |
| `SSH-Patator` | 5,897 | 0.21% | Multi-threaded SSH credential brute forcing |
| `DoS slowloris` | 5,796 | 0.20% | Low-bandwidth HTTP connection exhaustion |
| `DoS Slowhttptest` | 5,499 | 0.19% | Slow HTTP request DoS |
| `Bot` | 1,966 | 0.07% | Ares botnet C2 communications |
| `Web Attack – Brute Force`| 1,507 | 0.05% | HTTP form password brute-force |
| `Web Attack – XSS` | 652 | 0.02% | Cross-Site Scripting injections |
| `Infiltration` | 36 | <0.01% | Internal host compromise / pivot |
| `Web Attack – Sql Injection`| 21 | <0.01% | SQL query manipulation attacks |
| `Heartbleed` | 11 | <0.01% | OpenSSL memory disclosure exploit |

---

## 🔍 3. Network Flow Features Categorization

CICFlowMeter calculates bidirectional network flow attributes characterized by the 5-tuple:
$$(Source\ IP,\ Source\ Port,\ Destination\ IP,\ Destination\ Port,\ Protocol)$$

### Group A: Flow Identification & Duration
1. **Destination Port:** Target port number (e.g. 80=HTTP, 443=HTTPS, 22=SSH). In PortScan attacks, destination ports vary widely across arbitrary ranges.
2. **Flow Duration:** Duration of the network flow in microseconds ($\mu s$). Port scans often exhibit microscopic durations because scanners do not maintain full sessions.

### Group B: Packet Counts & Lengths
3. **Total Fwd Packets:** Number of packets transmitted in the forward direction (source to destination).
4. **Total Backward Packets:** Number of packets sent in the reverse direction (destination to source). For PortScan, this is often 0 or 1.
5. **Total Length of Fwd Packets:** Cumulative payload size in bytes transmitted forward.
6. **Total Length of Bwd Packets:** Cumulative payload size in bytes returned.
7. **Fwd Packet Length Max / Min / Mean / Std:** Statistical dispersion of forward packet sizes.
8. **Bwd Packet Length Max / Min / Mean / Std:** Statistical dispersion of backward packet sizes.
9. **Min / Max / Mean / Std / Variance Packet Length:** Global packet size statistics across the entire bidirectional flow.
10. **Average Packet Size:** Mean size of all packets exchanged in the flow.

### Group C: Inter-Arrival Times (IAT)
*Inter-Arrival Time (IAT) measures the time elapsed between consecutive packets in a flow.*
11. **Flow IAT Mean / Std / Max / Min:** Statistical time intervals between any two packets in the flow.
12. **Fwd IAT Total / Mean / Std / Max / Min:** Time elapsed between forward packets.
13. **Bwd IAT Total / Mean / Std / Max / Min:** Time elapsed between backward packets.

### Group D: TCP Flags & Protocol State
*TCP flags convey connection setup, teardown, and urgency state.*
14. **Fwd PSH Flags / Bwd PSH Flags:** PUSH flag count (instructs receiver to push data to application immediately without buffering).
15. **Fwd URG Flags / Bwd URG Flags:** URGENT pointer flag count.
16. **FIN Flag Count:** Connection teardown flag.
17. **SYN Flag Count:** Connection initiation / synchronization flag. Crucial for SYN scans (`nmap -sS`), where SYN is sent without completing handshake.
18. **RST Flag Count:** Connection reset flag. Frequently generated when scanning closed ports.
19. **PSH Flag Count:** Total PUSH flag count in the flow.
20. **ACK Flag Count:** Acknowledgment flag count.
21. **URG Flag Count:** Urgent flag indicator.
22. **CWE Flag Count / ECE Flag Count:** Congestion notification flags (Explicit Congestion Notification).

### Group E: Flow Rates & Volume
23. **Flow Bytes/s:** Flow throughput in bytes per second. (Can produce `inf` if Flow Duration = 0).
24. **Flow Packets/s:** Flow throughput in packets per second.
25. **Fwd Packets/s / Bwd Packets/s:** Direction-specific packet rates.
26. **Down/Up Ratio:** Ratio of backward to forward packet volume.
27. **Fwd Avg Bytes/Bulk / Fwd Avg Packets/Bulk / Fwd Avg Bulk Rate:** Bulk data transfer statistics for forward direction.
28. **Bwd Avg Bytes/Bulk / Bwd Avg Packets/Bulk / Bwd Avg Bulk Rate:** Bulk data transfer statistics for backward direction.

### Group F: Subflow & TCP Window Attributes
29. **Subflow Fwd Packets / Bytes:** Average number of packets/bytes in a subflow forward.
30. **Subflow Bwd Packets / Bytes:** Average number of packets/bytes in a subflow backward.
31. **Init_Win_bytes_forward:** Number of bytes sent in the initial TCP window in forward direction (indicates OS TCP stack fingerprint).
32. **Init_Win_bytes_backward:** Number of bytes sent in initial TCP window backward.
33. **act_data_pkt_fwd:** Count of forward packets with at least 1 byte of TCP data payload. For stealth scans, this is typically 0.
34. **min_seg_size_forward:** Minimum segment size observed in forward direction (minimum TCP header size).

### Group G: Active & Idle Timing
35. **Active Mean / Std / Max / Min:** Time duration a flow was active before going idle.
36. **Idle Mean / Std / Max / Min:** Time duration a flow was idle before becoming active again.

---

## 🧹 4. Preprocessing Notes & Caveats

1. **Whitespace in Headers:**
   The raw CSVs contain leading spaces in almost all column headers (e.g. `' Destination Port'`, `' Label'`).
   *Solution:* Always apply `.columns = df.columns.str.strip()` upon loading.

2. **Division by Zero (`np.inf`):**
   If `Flow Duration` is recorded as 0 microseconds, `Flow Bytes/s` and `Flow Packets/s` result in IEEE floating-point infinity (`inf`).
   *Solution:* Replace `[np.inf, -np.inf]` with `np.nan` and drop using `dropna()`.

3. **Constant Columns:**
   Several columns in the dataset have standard deviation = 0 (same value across every single row, e.g. `Bwd PSH Flags`, `Fwd URG Flags`, `Fwd Avg Bytes/Bulk`).
   *Solution:* Drop them using `df.loc[:, df.nunique() > 1]` to reduce dimensionality without losing information.
