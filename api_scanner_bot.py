import asyncio
import json
import tkinter as tk
from tkinter import ttk, scrolledtext
from playwright.async_api import async_playwright
import pandas as pd
import requests
import tldextract
import shodan
import scapy.all as scapy
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import SVC
import socket

# Load Shodan API Key from environment variable
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get Shodan API Key from environment variable
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")  # Shodan API key for vulnerability scanning

# AI Model for Phishing Detection
def train_ai_model():
    training_data = ["legitimate site", "secure website", "phishing attempt", "malware site", "trusted page"]
    labels = [0, 0, 1, 1, 0]  # 0 = Safe, 1 = Dangerous

    vectorizer = TfidfVectorizer()
    X_train = vectorizer.fit_transform(training_data)
    model = SVC(kernel="linear", probability=True)
    model.fit(X_train, labels)
    return model, vectorizer

ai_model, ai_vectorizer = train_ai_model()

# Function to extract APIs & Network Requests
async def extract_api_data():
    website_url = url_entry.get()
    if not website_url:
        result_text.insert(tk.END, "⚠ Please enter a website URL\n")
        return
    if not website_url.startswith(("http://", "https://")):
        result_text.insert(tk.END, "⚠ Please enter a valid URL starting with http:// or https://\n")
        return
    
    result_text.insert(tk.END, f"🔍 Scanning {website_url} ...\n")
    
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()
            
            network_data = []
            
            async def log_request(request):
                try:
                    request_data = {
                        "URL": request.url,
                        "Method": request.method,
                        "Request Headers": request.headers,
                        "Payload": request.post_data if request.post_data else "N/A",
                    }
                    network_data.append(request_data)
                except Exception as e:
                    result_text.insert(tk.END, f"⚠ Error logging request: {str(e)}\n")
            
            async def log_response(response):
                try:
                    for req in network_data:
                        if req["URL"] == response.url:
                            req["Response Headers"] = response.headers
                            req["Status Code"] = response.status
                            try:
                                body = await response.body()
                                req["Response Body"] = body[:500] if body else "Empty response body"
                            except:
                                req["Response Body"] = "Unable to fetch response body"
                except Exception as e:
                    result_text.insert(tk.END, f"⚠ Error logging response: {str(e)}\n")
            
            page.on("request", log_request)
            page.on("response", log_response)
            
            try:
                await page.goto(website_url, wait_until="networkidle", timeout=30000)
                
                local_storage = await page.evaluate("() => JSON.stringify(localStorage)")
                session_storage = await page.evaluate("() => JSON.stringify(sessionStorage)")
                
                api_requests = [req for req in network_data if "/api/" in req["URL"] or "api." in req["URL"].lower()]
                
                html_content = await page.content()
                soup = BeautifulSoup(html_content, "lxml")
                meta_tags = {meta.get("name", ""): meta.get("content", "") for meta in soup.find_all("meta")}
                
                cookies = await context.cookies()
                
                website_text = soup.get_text()
                X_test = ai_vectorizer.transform([website_text])
                prediction = ai_model.predict(X_test)[0]
                phishing_result = "⚠ This website might be unsafe!" if prediction == 1 else "✅ This website looks safe."
                
                result_text.insert(tk.END, "\n✅ API Requests Found:\n")
                if api_requests:
                    for api in api_requests:
                        result_text.insert(tk.END, f"🔗 {api['URL']}\n")
                        result_text.insert(tk.END, f"   Method: {api['Method']}\n")
                        result_text.insert(tk.END, f"   Status: {api.get('Status Code', 'Unknown')}\n")
                else:
                    result_text.insert(tk.END, "❌ No API endpoints found.\n")
                
                result_text.insert(tk.END, "\n📌 Local Storage Data:\n")
                result_text.insert(tk.END, f"{json.loads(local_storage)}\n\n")
                
                result_text.insert(tk.END, "\n📌 Session Storage Data:\n")
                result_text.insert(tk.END, f"{json.loads(session_storage)}\n\n")

                result_text.insert(tk.END, "\n🌍 Meta Information:\n")
                for key, value in meta_tags.items():
                    if key and value:
                        result_text.insert(tk.END, f"{key}: {value}\n")
                
                result_text.insert(tk.END, "\n🍪 Cookies Found:\n")
                for cookie in cookies:
                    try:
                        name = cookie.get('name', 'Unknown')
                        value = cookie.get('value', 'N/A')
                        domain = cookie.get('domain', 'N/A')
                        result_text.insert(tk.END, f"{name} ({domain}): {value}\n")
                    except Exception as e:
                        result_text.insert(tk.END, f"Error processing cookie: {str(e)}\n")
                
                result_text.insert(tk.END, f"\n🔍 AI Phishing Analysis: {phishing_result}\n")

                # Save network logs
                df = pd.DataFrame(network_data)
                df.to_csv("scan_results/network_logs/network_logs.csv", index=False)
                
                # Save API information
                api_df = pd.DataFrame(api_requests)
                api_df.to_csv("scan_results/api_info/api_requests.csv", index=False)
                
                # Save storage data
                storage_data = {
                    "local_storage": json.loads(local_storage),
                    "session_storage": json.loads(session_storage),
                    "cookies": cookies
                }
                with open("scan_results/storage_data/storage_info.json", "w") as f:
                    json.dump(storage_data, f, indent=4)
                
                result_text.insert(tk.END, "📂 Data saved in scan_results folder\n")
            except Exception as e:
                result_text.insert(tk.END, f"⚠ Error during page scan: {str(e)}\n")
            finally:
                await browser.close()
    except Exception as e:
        result_text.insert(tk.END, f"⚠ Critical error: {str(e)}\n")

# Function to check website vulnerabilities using Shodan
async def check_vulnerabilities():
    website_url = url_entry.get()
    if not website_url:
        result_text.insert(tk.END, "⚠ Please enter a website URL first\n")
        return
    
    domain_info = tldextract.extract(website_url)
    domain = f"{domain_info.domain}.{domain_info.suffix}"
    
    result_text.insert(tk.END, f"\n🛡 Checking security risks for {domain}...\n")
    
    try:
        # Validate API key first
        if not SHODAN_API_KEY:
            result_text.insert(tk.END, "⚠ Please configure a valid Shodan API key first\n")
            return

        shodan_api = shodan.Shodan(SHODAN_API_KEY)
        try:
            # Test API key validity
            api_info = await asyncio.to_thread(shodan_api.info)
            result_text.insert(tk.END, f"✅ Connected to Shodan API (Credits remaining: {api_info.get('query_credits', 'Unknown')})\n")
        except shodan.APIError as e:
            if "401" in str(e) or "403" in str(e):
                result_text.insert(tk.END, "⚠ Invalid Shodan API key. Please update your API key\n")
                return
            raise e

        # First try to resolve the domain to IP
        try:
            try:
                resolved_ip = socket.gethostbyname(domain)
                if not resolved_ip:
                    result_text.insert(tk.END, f"⚠ Could not resolve domain {domain} to IP address\n")
                    return
            except socket.gaierror:
                result_text.insert(tk.END, f"⚠ Could not resolve domain {domain} to IP address\n")
                return
            
            ips = await asyncio.to_thread(shodan_api.host, resolved_ip)
            ips = [resolved_ip]  # Convert single IP to list for consistency
            result_text.insert(tk.END, f"📡 Found {len(ips)} IP addresses for {domain}\n")
            
            all_findings = []
            for ip in ips:
                try:
                    # Get detailed host information
                    host_info = await asyncio.to_thread(shodan_api.host, ip)
                    all_findings.append(host_info)
                except shodan.APIError as e:
                    if "No information available" in str(e):
                        result_text.insert(tk.END, f"ℹ️ No Shodan data available for IP: {ip}\n")
                        continue
                    else:
                        raise e
            
            if all_findings:
                result_text.insert(tk.END, f"🔴 Found security information for {len(all_findings)} hosts!\n")
                for host in all_findings:
                    result_text.insert(tk.END, f"\n📍 Host: {host.get('ip_str', 'Unknown')}")
                    result_text.insert(tk.END, f"\n   Organization: {host.get('org', 'Unknown')}")
                    result_text.insert(tk.END, f"\n   Country: {host.get('country_name', 'Unknown')}")
                    
                    # Show open ports
                    ports = host.get('ports', [])
                    if ports:
                        result_text.insert(tk.END, f"\n   🔓 Open Ports: {', '.join(map(str, ports[:5]))}")
                    
                    # Show vulnerabilities
                    vulns = host.get('vulns', [])
                    if vulns:
                        result_text.insert(tk.END, f"\n   🚨 CVEs: {', '.join(list(vulns)[:3])}")
                    
                    # Show services
                    for service in host.get('data', [])[:3]:
                        port = service.get('port', 'Unknown')
                        product = service.get('product', 'Unknown')
                        version = service.get('version', 'Unknown')
                        result_text.insert(tk.END, f"\n   Service: {product} {version} on port {port}")
                
                # Save findings to file
                security_data = {
                    "domain": domain,
                    "scan_time": str(pd.Timestamp.now()),
                    "findings": all_findings
                }
                with open("scan_results/security_findings/security_scan.json", "w") as f:
                    json.dump(security_data, f, indent=4)
                result_text.insert(tk.END, "\n📂 Security findings saved to scan_results/security_findings/security_scan.json\n")
            else:
                result_text.insert(tk.END, "✅ No security findings available for this domain\n")
        except shodan.APIError as e:
            result_text.insert(tk.END, f"⚠ Error resolving domain: {str(e)}\n")
    except shodan.APIError as e:
        result_text.insert(tk.END, f"⚠ Shodan API error: {str(e)}\n")
    except Exception as e:
        result_text.insert(tk.END, f"⚠ Error fetching security info: {str(e)}\n")

# Create UI using Tkinter
root = tk.Tk()
root.title("Ultimate Website Scanner")
root.geometry("800x600")

frame = ttk.Frame(root, padding="10")
frame.pack(fill="both", expand=True)

ttk.Label(frame, text="Enter Website URL:").pack(pady=5)
url_entry = ttk.Entry(frame, width=50)
url_entry.pack(pady=5)

async def run_scan():
    try:
        await extract_api_data()
    except Exception as e:
        result_text.insert(tk.END, f"⚠ Error during scan: {str(e)}\n")

scan_button = ttk.Button(frame, text="Scan Website", command=lambda: asyncio.run(run_scan()))
scan_button.pack(pady=5)

security_button = ttk.Button(frame, text="Check Security", command=lambda: asyncio.run(check_vulnerabilities()))
security_button.pack(pady=5)

result_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=20)
result_text.pack(fill="both", expand=True, pady=5)

root.mainloop()