# File Firewall: End-to-End Secure File Protection with Brute-Force Defense, MFA, Falco Runtime Security, and Terraform Automation

##  Project Overview

**File Firewall** is a secure file management system that protects sensitive data using robust encryption, brute-force attack defense, Google Authenticator MFA, and admin-controlled recovery. 
This project is containerized with Docker, secured at runtime with Falco, and fully automated using Terraform Infrastructure as Code (IaC).

This project shows how security can be integrated across the entire lifecycle — from development to deployment to runtime monitoring — following real-world DevSecOps practices.

---

## Key Features

- **Strong File Encryption:** AES-256 encryption with secure hashing.
- **Brute-Force Defense:** Automatic file evacuation to a hidden vault after three failed password attempts.
- **Multi-Factor Authentication (MFA):** Google Authenticator integration for critical operations.
- **Admin Recovery Mode:** Secure recovery of evacuated files by authorized admins.
- **Detailed Logging:** Tracks all actions for auditing and compliance.
- **Containerized Deployment:** Runs in Docker for portability and consistency.
- **Runtime Threat Detection:** Falco monitors container behavior in real time.
- **Automated Infrastructure:** Terraform provisions and deploys the entire environment.

---

## ⚙ How It Works

1. Users upload and encrypt sensitive files with a strong password.
2. After three failed attempts, the file is automatically evacuated to a hidden vault.
3. Google Authenticator MFA is required for critical file operations.
4. Admins can securely restore evacuated files via the recovery portal.
5. Falco monitors the running container for any suspicious behavior.
6. Terraform automates build, deployment, and container orchestration.

---

##  Tech Stack

- **Python + Flask:** Backend and GUI.
- **Cryptography Library:** AES-256 encryption.
- **Google Authenticator:** Time-based MFA.
- **Docker:** Containerization.
- **Falco:** Runtime container threat detection.
- **Terraform:** Infrastructure as Code.

---

##  Project Structure
file-firewall/
├── Dockerfile
├── main.tf
├── app.py
├── file_firewall.py
├── file_firewall_gui.py
├── recover_file.py
├── calculate_hash.py
├── requirements.txt
├── hidden_vault/
├── templates/
├── static/
├── log.txt
└── README.md


---

##  Getting Started

1. clone the repository
```bash
git clone https://github.com/YOUR-USERNAME/file-firewall.git
cd file-firewall
2. Deploy with Terraform
terraform init
terraform plan
terraform apply
3. Access the Application

Open your browser and visit:
http://localhost:8080

4. Monitor Security Events

View Falco runtime logs to see container threats:
docker logs -f falco




Author
Pradeep Reddy Nalagouni
Cybersecurity & DevSecOps and cloud security enthusiast dedicated to building secure, automated, and resilient systems.



