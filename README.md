# PacketSpy-X

### Real-Time Network Intrusion Detection and Monitoring System

PacketSpy-X is a lightweight Python-based network monitoring and basic intrusion detection system developed as a B.Sc. Computer Science final-year project.

It captures live network packets using Scapy, analyzes packet-level information, applies rule-based and statistical anomaly detection, enriches selected IP addresses using OSINT, stores data in SQLite, and presents network activity through a Flask web dashboard.

---

## Features

- Real-time packet capture and monitoring
- Rule-based suspicious activity detection
- Z-score based anomaly detection
- IP address OSINT enrichment
- Packet and threat data storage using SQLite
- Real-time web dashboard
- Risk and severity classification

## Architecture

```text
Network Interface
       │
       ▼
Packet Capture
    (Scapy)
       │
       ▼
Packet Processing
       │
       ├───────────────┐
       ▼               ▼
Rule-Based        Z-Score
Detection         Analysis
       │               │
       └───────┬───────┘
               ▼
        Risk / Severity
               │
       ┌───────┴───────┐
       ▼               ▼
   SQLite            OSINT
   Storage           Lookup
       │               │
       └───────┬───────┘
               ▼
       Flask Dashboard
Detection

The system combines rule-based checks with statistical anomaly detection.

Rule-Based Detection

The implementation monitors indicators such as:

High packet frequency
SYN activity
Unusual port activity
Repeated connection attempts
Z-Score Anomaly Detection
Z = (X - μ) / σ

Where:

X = observed traffic value
μ = average traffic
σ = standard deviation

The research implementation uses approximately:

Z > 2  → Moderately unusual
Z > 3  → Highly suspicious
Technology
Python
Flask
Scapy
SQLite
Requests
python-whois
Chart.js
HTML
CSS
JavaScript
Project Structure
packetspy-x/
│
├── app.py
├── packet_sniffer.py
├── database.py
├── config.py
├── osint.py
├── requirements.txt
│
├── templates/
│   ├── index.html
│   └── login.html
│
├── static/
│   ├── script.js
│   └── style.css
│
└── docs/
    └── publication.md
Installation
python -m venv .venv

Activate the virtual environment and install the dependencies:

pip install -r requirements.txt

Run the application:

python app.py

The Flask application runs on port 5000.

Packet capture should only be performed on systems and networks where you have appropriate authorization.

Research Publication
PacketSpy-X: A Real-Time Network Intrusion Detection and Monitoring System

Published in the International Journal of Research Publication and Reviews, Vol. 7, Issue 3, March 2026, pp. 4621–4624.
https://ijrpr.com/uploads/V7ISSUE3/IJRPR61084.pdf

Author

Krishna Raj R

B.Sc. Computer Science — First Class with Distinction
Currently pursuing M.Sc. Computer Science

PacketSpy-X: A Real-Time Network Intrusion Detection and Monitoring System

Published in the International Journal of Research Publication and Reviews, Vol. 7, Issue 3, March 2026, pp. 4621–4624.
