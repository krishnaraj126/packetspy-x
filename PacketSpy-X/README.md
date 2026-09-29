# PacketSpy-X

**Real-Time Network Intrusion Detection and Monitoring System**

PacketSpy-X is a lightweight Python-based network monitoring and basic intrusion detection application developed as a B.Sc. Computer Science final-year project.

The system captures live IP traffic with **Scapy**, extracts packet-level information, applies **rule-based checks** and **Z-score anomaly detection**, enriches selected IP information with **OSINT**, stores packet records in **SQLite**, and presents monitoring data through a **Flask web dashboard**.

## Research

**Published paper:**  
*PacketSpy-X: A Real-Time Network Intrusion Detection and Monitoring System*  
International Journal of Research Publication and Reviews, Vol. 7, Issue 3, March 2026, pp. 4621–4624.

**Paper:** https://ijrpr.com/uploads/V7ISSUE3/IJRPR61084.pdf

## Architecture

```text
Network Interface
       |
       v
Packet Capture (Scapy)
       |
       v
Packet Processing
       |
       +--------------------+
       |                    |
       v                    v
Rule-Based Detection   Z-Score Anomaly Detection
       |                    |
       +---------+----------+
                 |
                 v
          Risk / Severity
                 |
       +---------+----------+
       |                    |
       v                    v
   SQLite Storage        OSINT Lookup
       |                    |
       +---------+----------+
                 |
                 v
          Flask Dashboard
```

## Detection approach

The current implementation uses:

- SYN activity tracking
- Port-activity tracking
- Packet-frequency checks
- Z-score based traffic anomaly detection
- A simple rule-based risk score
- Severity classification

The research paper documents the Z-score method as:

```text
Z = (X - μ) / σ
```

with the project using thresholds of approximately `Z > 2` for moderately unusual traffic and `Z > 3` for highly suspicious traffic.

## Technologies

- Python
- Flask
- Scapy
- SQLite
- Requests
- python-whois
- Chart.js
- HTML / CSS / JavaScript

## Project structure

```text
packetspy-x/
├── app.py
├── packet_sniffer.py
├── database.py
├── config.py
├── osint.py
├── requirements.txt
├── templates/
│   ├── index.html
│   └── login.html
├── static/
│   ├── script.js
│   └── style.css
└── docs/
    └── publication.md
```

## Running locally

Create a virtual environment and install dependencies:

```bash
python -m venv .venv
```

Activate it, then:

```bash
pip install -r requirements.txt
```

Run:

```bash
python app.py
```

The Flask application listens on port `5000`.

> Packet capture generally requires appropriate privileges and should only be performed on networks and systems where you have permission.

## Important note

This repository contains the recovered source from the original B.Sc. project. It is preserved as a portfolio/research artifact; future improvements can be developed separately as a new version rather than silently rewriting the original implementation.

## Author

**Krishna Raj R**

B.Sc. Computer Science — First Class with Distinction  
Currently pursuing M.Sc. Computer Science
