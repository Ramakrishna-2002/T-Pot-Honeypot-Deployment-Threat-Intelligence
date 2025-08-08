T-Pot Honeypot Deployment & Threat Analysis
📌 Project Overview
This project focuses on deploying and analysing T-Pot, a multi-honeypot platform, in a cloud environment to detect, log, and analyse cyber-attacks in real-time. The deployment was performed on Google Cloud Platform (GCP) and ran continuously from October 9, 2023, capturing over 4 million attacks across multiple honeypot services.

The goal was to:

Simulate vulnerable systems to attract malicious actors.

Collect and analyse attack data.

Identify patterns, sources, and methods used by attackers.

Recommend proactive cybersecurity measures.

🛠 Technologies & Tools Used
Google Cloud Platform (GCP) – Virtual Machine deployment

Debian 11 (Bullseye) – Base OS for VM

T-Pot Honeypot Framework – Multi-honeypot deployment

Docker – Containerized honeypot instances

Kibana (ELK Stack) – Data visualization and dashboarding

MITRE ATT&CK, VirusTotal, AbuseIPDB – Threat intelligence and enrichment tools

⚙️ Honeypots Deployed
Ddospot – Detects DDoS-related traffic.

Cowrie – SSH and Telnet honeypot.

Dionaea – Captures malware samples targeting network services.

Additional honeypots for mobile security (ADBHoney), email security (Maloney), and industrial protocols.

☁️ Deployment Architecture

Architecture Description:

Researcher Access – Connects to the GCP-hosted VM to manage deployment and monitor logs.

Google Cloud VM – Runs Debian 11 and hosts the T-Pot platform.

Honeypot Containers – Multiple services (Ddospot, Cowrie, Dionaea, etc.) simulate vulnerable systems.

ELK Stack – Collects, stores, and visualizes attack data in Kibana dashboards.

Threat Intelligence – Enriches data using MITRE ATT&CK, VirusTotal, and AbuseIPDB for attacker profiling.

📊 Key Results
Attack Summary
Honeypot Service	Total Attacks	Notable Sources
Ddospot	2,491,639	Brazil, USA
Cowrie	1,030,375	China, USA, Singapore
Dionaea	566,383	Vietnam, USA

🔍 Threat Intelligence Insights
Integrated MITRE ATT&CK mapping to classify attack techniques.

Verified suspicious IPs via VirusTotal and AbuseIPDB.

Identified over 1 million+ attacks related to phishing campaigns and botnet activity.

Significant credential-based attacks highlight weak password hygiene issues.

🛡 Recommendations
Enhanced DDoS mitigation — adopt rate-limiting, geo-blocking for high-risk regions.

Harden SSH access — enforce multi-factor authentication and disable root login.

Secure coding practices — regularly audit and patch web applications to prevent exploitation.

Threat intelligence sharing — collaborate with industry peers for real-time attack data exchange.

📂 Project Nature
This project was conducted as part of an MSc in Applied Cybersecurity.
It was purely cloud-based, with no source code files — all configurations and deployments were performed directly on a Linux VM in GCP.
