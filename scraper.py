import asyncio
import re
import sqlite3
from bs4 import BeautifulSoup
from crawl4ai import AsyncWebCrawler
from googlesearch import search
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import streamlit as st
from g4f.client import Client  # g4f integration for remediation generation

# Email configuration
from dotenv import load_dotenv
import os

load_dotenv()

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")


# Database setup
DB_NAME = "cve_monitor.db"

def init_db():
    """Initialize the database for storing brands and CVEs and load brands from file."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS cves (
                        brand TEXT, 
                        cve_id TEXT PRIMARY KEY, 
                        link TEXT, 
                        g4f_content TEXT
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS brands (
                        brand_name TEXT PRIMARY KEY
                    )''')
    conn.commit()

    # Load brands from nmap_results.txt
    try:
        with open("nmap_results.txt", "r") as f:
            brands = [line.strip() for line in f.readlines() if line.strip()]
            for brand in brands:
                save_brand_to_db(brand)
    except FileNotFoundError:
        st.error("nmap_results.txt file not found. Please make sure it is in the correct directory.")

    conn.close()

def extract_cves(content):
    """Extract CVEs from webpage content using regex."""
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    return re.findall(cve_pattern, content)

def clean_text(content):
    """Clean the text by removing excess whitespace."""
    return ' '.join(content.split())

def send_email_alert(brand, new_cves, g4f_responses, email_recipients):
    """Send an email alert containing the new g4f-generated CVE information and show it on UI."""
    if not new_cves:
        return  # No new CVEs, no need to send an email
    
    subject = f"New CVEs Disclosed for {brand}"
    body = f"The following new CVEs were disclosed for {brand}:\n\n"
    
    for g4f_response in g4f_responses:
        body += f"g4f Info:\n{g4f_response}\n\n"

    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = ", ".join(email_recipients)
    msg['Subject'] = subject
    
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_SENDER, email_recipients, text)
        server.quit()
        st.success("Email alert sent successfully!")

        # Display the sent email content on the UI
        st.markdown("### Sent Email Content:")
        st.text(f"Subject: {subject}\n\n{body}")
        
    except Exception as e:
        st.error(f"Failed to send email alert: {str(e)}")

async def scrape_for_cves(url):
    """Scrape a website for CVEs."""
    async with AsyncWebCrawler(verbose=True) as crawler:
        js_scroll = "window.scrollTo(0, document.body.scrollHeight);"
        result = await crawler.arun(url=url, js=js_scroll, bypass_cache=True)
        
        if not result.success:
            st.error(f"Failed to crawl {url}")
            return []
        
        soup = BeautifulSoup(result.cleaned_html, 'html.parser')
        text_content = soup.get_text()
        cves = extract_cves(text_content)
        
        return cves[:1]

def get_cve_link(cve_id):
    """Search for a CVE link on the internet."""
    query = f"{cve_id} site:cvedetails.com"
    try:
        return next(search(query, num_results=1))
    except StopIteration:
        return None

async def scrape_cve_details(cve_link):
    """Scrape the CVE details from the found link."""
    async with AsyncWebCrawler(verbose=True) as crawler:
        result = await crawler.arun(url=cve_link, bypass_cache=True)
        if not result.success:
            st.error(f"Failed to crawl {cve_link}")
            return ""
        
        soup = BeautifulSoup(result.cleaned_html, 'html.parser')
        content = soup.get_text()
        return clean_text(content)

# Function to get suggestions from g4f
def get_g4f_suggestions(cve_details):
    """Use g4f to get suggestions or remediation steps."""
    client = Client()
    response = client.chat.completions.create(
        model="blackbox",
        messages=[{"role": "user", "content": f"Please give properly formatted details and suggest remediation steps for the following CVE:\n{cve_details}" }]
    )
    return response.choices[0].message.content

def save_new_cves_to_db(brand, new_cves, g4f_responses):
    """Save new CVEs and their g4f-generated content to the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    for (cve_id, link), g4f_content in zip(new_cves, g4f_responses):
        cursor.execute('''INSERT OR IGNORE INTO cves (brand, cve_id, link, g4f_content) VALUES (?, ?, ?, ?)''', 
                       (brand, cve_id, link, g4f_content))
    conn.commit()
    conn.close()

def get_known_cves(brand):
    """Get known CVEs from the database for a specific brand."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''SELECT cve_id FROM cves WHERE brand = ?''', (brand,))
    known_cves = {row[0] for row in cursor.fetchall()}
    conn.close()
    return known_cves

def get_brand_cves(brand):
    """Retrieve all CVEs for a specific brand from the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''SELECT cve_id, g4f_content FROM cves WHERE brand = ?''', (brand,))
    cves = cursor.fetchall()
    conn.close()
    return cves

def save_brand_to_db(brand):
    """Save brand to the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''INSERT OR IGNORE INTO brands (brand_name) VALUES (?)''', (brand,))
    conn.commit()
    conn.close()

def get_all_brands():
    """Retrieve all brands from the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''SELECT brand_name FROM brands''')
    brands = cursor.fetchall()
    conn.close()
    return [b[0] for b in brands]

async def monitor_brand_site(brand, site_url, email_recipients):
    """Monitor a website for new CVEs for a specific brand."""
    known_cves = get_known_cves(brand)
    latest_cves = await scrape_for_cves(site_url)
    new_cves = []
    g4f_responses = []

    for cve in latest_cves:
        if cve not in known_cves:
            cve_link = get_cve_link(cve)
            if cve_link:
                cve_details = await scrape_cve_details(cve_link)
                remediation = get_g4f_suggestions(cve_details)  # Get suggestions from g4f
                new_cves.append((cve, cve_link))
                g4f_responses.append(remediation)
    
    if new_cves:
        st.success(f"New CVEs found for {brand}: {[cve[0] for cve in new_cves]}")
        save_new_cves_to_db(brand, new_cves, g4f_responses)
        send_email_alert(brand, new_cves, g4f_responses, email_recipients)
    else:
        st.info(f"No new CVEs for {brand}")

def find_vuln_sites(brand):
    """Find vulnerability disclosure sites using Google Dorking."""
    query = f"{brand} security advisories OR vulnerability disclosure OR security bulletins"
    return list(search(query, num_results=3))

def app():
    """Streamlit app interface."""
    st.set_page_config(layout="wide", page_title="Vulnerability Monitor")

    init_db()  # Initialize the database
    
    st.title("SIH 2024 - DISCLOSE TRACKER")
    st.markdown("---")
    
    # Sidebar to manage brands and email recipients
    with st.sidebar:
        st.header("Manage Brands & Emails")
        
        email_recipients = st.text_area("Enter recipient emails (comma separated)", 
                                        value="example@mail.com").split(',')
        
        new_brand = st.text_input("Add a new brand")
        if st.button("Add Brand"):
            if new_brand:
                save_brand_to_db(new_brand)
                st.success(f"Brand '{new_brand}' added to the database.")
            else:
                st.error("Please enter a valid brand name.")

        # Select a brand to monitor
        brands = get_all_brands()
        brand_selection = st.selectbox("Select a brand to monitor", brands)

    if st.button("Start Monitoring"):
        # Get vulnerability disclosure sites for the selected brand
        sites = find_vuln_sites(brand_selection)
        if not sites:
            st.warning(f"No vulnerability disclosure sites found for {brand_selection}.")
        else:
            for site in sites:
                st.write(f"Monitoring {site} for {brand_selection}...")
                asyncio.run(monitor_brand_site(brand_selection, site, email_recipients))

if __name__ == "__main__":
    app()

#--------------------------
