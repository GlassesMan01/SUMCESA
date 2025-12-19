# SUMCESA 🔐

**Security Update Management Tool for Cyber Essentials Self Assessment (SUMCESA)**

SUMCESA is a lightweight, automated tool for managing software updates, tracking installed software, and assessing vulnerabilities using CVE/NVD data. It provides a centralized web dashboard to visualize security posture, monitor updates, and generate automated compliance reports.

This project was developed as a hands-on learning initiative to gain practical experience in cybersecurity automation, cross-platform system administration, and full-stack development.

---

## 📌 Overview

**SUMCESA (Security Update Management CE Self-Assessment)** is a centralized platform that demonstrates how small organizations can:

- Maintain software inventories
- Monitor update status
- Assess vulnerabilities using CVE/NVD data
- Generate security and compliance reports

The focus of this project is **practical cybersecurity implementation**, not commercial deployment.

---

## 🎯 Project Objectives

This project was developed to gain experience in:

- Security automation workflows
- Vulnerability assessment using CVE & CVSS
- Cross-platform system administration (Windows & Linux)
- Web-based dashboards for security monitoring
- Secure and maintainable application architecture

---

## ✨ Key Features

### 1️⃣ Automated Software Discovery

- System-wide software inventory
- Version detection and comparison
- Update availability tracking

### 2️⃣ Vulnerability Assessment

- Real-time CVE lookup via NVD API
- CVSS-based risk scoring
- Prioritized vulnerability listings

### 3️⃣ Centralized Web Dashboard

- Real-time system monitoring
- Interactive charts and summaries
- One-click report generation

### 4️⃣ Multi-Platform Support

- **Windows**: WMI / PowerShell automation
- Centralized control through web interface

### 5️⃣ Automated Reporting

- Security status summaries
- Compliance-style checklists
- Remediation recommendations

---

## 🖼️ Project Screenshots

> Screenshots are provided for demonstration purposes.

### Dashboard

![Dashboard](https://github.com/GlassesMan01/SUMCESA/blob/main/Project%20Images/Dashboard.png)  
_Main control panel showing system overview and vulnerability summary_

### Software Inventory

![Software Inventory](https://github.com/GlassesMan01/SUMCESA/blob/main/Project%20Images/Software%20Inventory.png)  
_Installed software with version tracking_

### Software Updates

![Software Updates](https://github.com/GlassesMan01/SUMCESA/blob/main/Project%20Images/Software%20Updates.png)  
_Available updates across monitored systems_

### Vulnerability Details

![CPE Details](https://github.com/GlassesMan01/SUMCESA/blob/main/Project%20Images/CPE%20Details.png)  
_Detailed vulnerability information_

![CVE List](https://github.com/GlassesMan01/SUMCESA/blob/main/Project%20Images/CVE's.png)  
_CVE database lookup with severity ratings_

### System Management

![Machines](https://github.com/GlassesMan01/SUMCESA/blob/main/Project%20Images/Machines.png)  
_Monitored systems and agent status_

![Connection Way](https://github.com/GlassesMan01/SUMCESA/blob/main/Project%20Images/Connection%20Way.png)  
_Agent installation and communication flow_

### Reporting

![AI Generated Report](https://github.com/GlassesMan01/SUMCESA/blob/main/Project%20Images/AI%20Generated%20Report.png)  
_Automated security report with remediation guidance_

### Configuration

![Settings](https://github.com/GlassesMan01/SUMCESA/blob/main/Project%20Images/Settings.png)  
_System configuration and management options_

---

## 🛠️ Technology Stack

### Backend

- Python 3.8+
- Flask (RESTful architecture)
- SQLAlchemy ORM
- Requests (API communication)
- WMI / PowerShell (Windows automation)
- apt / dnf (Linux automation)

### Frontend

- HTML5 / CSS3
- Jinja2 templating
- Bootstrap (UI components)
- Chart.js (data visualization)

### Database

- SQLite (development / lightweight)
- MySQL (production-ready option)

### APIs & Services

- NVD API (CVE & CVSS data)
- Custom REST API for agent communication
- Groq Llama API for report generation

---

## 🚀 Getting Started

### 📥 Installation

```bash
git clone [https://github.com/yourusername/SUMCESA.git](https://github.com/GlassesMan01/SUMCESA.git)
cd SUMCESA
pip install -r requirements.txt
````

### ⚙️ Configuration
```bash
cp .env.example .env
# Edit .env and add required API keys
```

### ▶️ Run the Application
```bash
python app.py
```
Open your browser and navigate to:
http://localhost:5000

---

## 🧩 Agent Deployment
The system includes lightweight agents for data collection:
- Windows: PowerShell / Batch scripts
- Central Management: Web dashboard for monitoring agent status

---

## 🔍 How It Works
1. Data Collection
Agents scan installed software and system details
2. Vulnerability Matching
Software versions are checked against CVE/NVD data
3. Risk Analysis
CVSS scores are used to prioritize vulnerabilities
4. Dashboard Visualization
Results displayed via web interface
5. Reporting
Automated security and remediation reports generated

---

## 📚 Learning Outcomes
### Technical Skills
- Full-stack application development
- Security automation workflows
- Vulnerability management (CVE / CVSS)
- System integration and API usage
- Database design and ORM usage

### Professional Skills
- Project planning and architecture design
- Technical documentation
- Debugging and troubleshooting
- Version control with Git
- UX design for security data

---

## 🔮 Future Enhancements
Potential improvements include:
- Docker-based deployment
- Public REST API for integrations
- Mobile companion application
- Advanced analytics & ML-based risk prediction
- Plugin architecture for extensibility

---

## 🤝 Contributing
This is primarily a learning and research project, but contributions and suggestions are welcome.
1. Fork the repository
2. Create a feature branch
3.Commit your changes
4. Submit a pull request

---

## ⚠️ Disclaimer
This tool is intended for educational and defensive security purposes only.
Do not use it on systems you do not own or have explicit permission to test.

---

## 📄 License
This project is licensed under the [ MIT License](https://github.com/GlassesMan01/SUMCESA/blob/main/LICENSE).

---

## 💭 Personal Reflection
Building SUMCESA was an intensive hands-on learning experience (~200+ hours) that helped me:
- Translate cybersecurity theory into real tools
- Design scalable security automation systems
- Handle real-world data accuracy and performance issues
- Build user-friendly interfaces for technical audiences
- SUMCESA represents my growth across cybersecurity, automation, and software engineering.
