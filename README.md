# Disclose Tracker

## Problem Statement
**Title**: Web-scraping tool to search and report Critical and High Severity Vulnerabilities of OEM equipment published on respective OEM websites.

This tool is designed to monitor OEM websites, identify CVEs (Common Vulnerabilities and Exposures) related to their equipment, and send email alerts with remediation steps. It ensures timely updates for vulnerabilities of critical and high severity.

---
For prototype, refer to the [Demo photos](./Demo%20photos)
## Features
- Automatically scrapes websites for vulnerabilities using CVE patterns.
- Sends email alerts with detailed vulnerability reports and remediation suggestions.
- Monitors websites periodically (every 24 hours).
- User-friendly Streamlit interface for managing brands and viewing CVEs.
- Containerized deployment with Docker for seamless setup and portability.

For more details, refer to the [Documentation](./Disclose_Tracker.pdf)

---

## Usage

### **Without Docker**
In the current directory of project - 
```bash
pip install -r requirements.txt
```
Once all requirements are installed - 
```bash
streamlit run scraper.py
```

### **Using Docker**
Follow these steps to use the tool with Docker:

1. **Build the Docker Image**  
- Run the following command in the directory containing your files:  
```bash
docker-compose build
```
2. **Run the containers** 
- Start the application and background services using:
```bash
docker-compose up
```
3. **Access the Application**
 - Open your browser and navigate to:
http://localhost:8501
4. **Stop the Containers**
- When you're done, stop the containers with:
```bash
docker-compose down
```
