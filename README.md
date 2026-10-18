# Network Intrusion Detection System (NIDS)

## Project Overview

This project is an educational, Python-based Network Intrusion Detection System (NIDS) prototype that identifies suspicious TCP connection patterns using custom detection rules. It records security alerts in a JSON file and displays them through an interactive Streamlit dashboard.

## Objectives

- Detect potential TCP port-scanning activity.
- Identify unusually high TCP connection-attempt rates.
- Generate severity-based security alerts.
- Store alerts for later analysis.
- Visualize security events and export alert logs.

## Technologies Used

- Python
- Scapy
- Streamlit
- Pandas
- JSON

## Features

- **Port Scan Detection:** Detects TCP SYN packets targeting 10 or more unique destination ports within 10 seconds.
- **High Connection-Rate Detection:** Detects 20 or more TCP SYN packets from a source within 10 seconds.
- **Severity-Based Alerts:** Classifies port-scan alerts as High and high-connection-rate alerts as Medium.
- **JSON Alert Logging:** Stores timestamps, source and destination IP addresses, event types, severity, and details.
- **Interactive Dashboard:** Displays alert counts, severity charts, and recent security events.
- **CSV Export:** Allows users to download the alert log.
- **Simulated Testing:** Tests detection rules using Scapy-generated packets.

## Project Structure

```text
CODSOFT_TASK4/
├── nids_engine.py
├── test_nids.py
├── live_monitor.py
├── dashboard.py
├── alerts.json
├── requirements.txt
├── README.md
├── LICENSE
└── screenshots/
```

## Installation

Install Python 3.10 or later, then open a terminal in the project directory.

Install the required dependencies:

```bash
py -m pip install -r requirements.txt
```

## Run the Detection Tests

Execute:

```bash
py test_nids.py
```

The tests simulate TCP SYN traffic and verify both custom detection rules.

Expected result:

```text
PASS: Port scan detection rule triggered.
PASS: High connection-rate rule triggered.

ALL TESTS PASSED.
PASS: Alerts saved to alerts.json.
```

## Run the Dashboard

Start the Streamlit dashboard:

```bash
py -m streamlit run dashboard.py
```

Open the local URL displayed in the terminal, usually `http://localhost:8501`.

The dashboard displays alert totals, severity summaries, recent events, and a CSV download option.

## Live Packet Monitoring

The project includes `live_monitor.py` for optional live packet capture through Scapy. On Windows, live capture requires a compatible packet-capture driver such as Npcap and appropriate permissions.

Live packet capture has not been verified in this environment. The demonstrated detection results are based on simulated packets.

## Limitations

- This is an educational prototype, not a replacement for a production NIDS.
- The detection rules use simple thresholds and may produce false positives or miss attacks.
- The current rules focus on TCP SYN patterns.
- The prototype does not automatically block traffic.
- Alerts from simulated packets do not prove that a real attack occurred.
- It is not a Snort or Suricata deployment.

## Ethical Use

Use live monitoring only on devices and networks you own or are explicitly authorized to inspect. Do not use this project to intercept other people's traffic without permission.

## Author

Developed as part of the CodSoft Cyber Security Internship.
