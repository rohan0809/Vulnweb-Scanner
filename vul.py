# import json
# import requests
# from bs4 import BeautifulSoup
# import re

# # Define a list to store vulnerability findings
# vulnerabilities = []

# # Function to check for potential SQL injection
# def check_sql_injection(url, text):
#     sql_injection_patterns = ["SELECT * FROM", "DROP TABLE", "UNION ALL SELECT"]
#     for pattern in sql_injection_patterns:
#         if re.search(pattern, text, re.IGNORECASE):
#             vulnerabilities.append({
#                 "URL": url,
#                 "Vulnerability": "Potential SQL Injection",
#                 "Severity": "High",
#                 "Recommended Action": "Review and secure the SQL query."
#             })

# # Function to check for potential XSS (Cross-Site Scripting)
# def check_xss(url, text):
#     xss_patterns = ["<script>", "alert(", "onerror=", "javascript:"]
#     for pattern in xss_patterns:
#         if pattern in text:
#             vulnerabilities.append({
#                 "URL": url,
#                 "Vulnerability": "Potential XSS (Cross-Site Scripting)",
#                 "Severity": "Medium",
#                 "Recommended Action": "Review and sanitize user inputs and output encoding."
#             })

# # Function to check for potential CSRF (Cross-Site REQUEST FORGERY)
# def check_csrf(url, text):
#     csrf_patterns = ["<form action=", "<input type=\"hidden\" name=\"csrf_token\""]
#     for pattern in csrf_patterns:
#         if pattern in text:
#             vulnerabilities.append({
#                 "URL": url,
#                 "Vulnerability": "Cross-Site Request Forgery (CSRF)",
#                 "Severity": "High",
#                 "Recommended Action": "Implement anti-CSRF tokens and secure state-changing requests."
#             })

# # Function to check for potential Insecure File Upload
# def check_insecure_file_upload(url, text):
#     insecure_file_upload_patterns = ["<input type=\"file\"", "multipart/form-data"]
#     for pattern in insecure_file_upload_patterns:
#         if pattern in text:
#             vulnerabilities.append({
#                 "URL": url,
#                 "Vulnerability": "Potential Insecure File Upload",
#                 "Severity": "Medium",
#                 "Recommended Action": "Implement strict validation for file uploads, store uploads in a secure location, and restrict file types."
#             })

# def crawl_website(url, depth):
#     if depth == 0:
#         return

#     try:
#         response = requests.get(url)
#         if response.status_code == 200:
#             soup = BeautifulSoup(response.text, 'html.parser')
#             print(f"Crawling: {url}")

#             # Check for vulnerabilities on the current page
#             check_sql_injection(url, response.text)
#             check_xss(url, response.text)
#             check_csrf(url, response.text)  # Add CSRF check
#             check_insecure_file_upload(url, response.text)  # Add Insecure File Upload check

#             # Recursively crawl links on the current page
#             for link in soup.find_all('a'):
#                 next_url = link.get('href')
#                 if next_url and next_url.startswith('http'):
#                     crawl_website(next_url, depth - 1)
#     except Exception as e:
#         print(f"Error crawling {url}: {e}")

# if __name__ == '__main__':
#     start_url = 'https://www.javatpoint.com/'  # Replace with the target website
#     max_depth = 1 # Maximum depth for crawling

#     crawl_website(start_url, max_depth)

#     # Generate a report in JSON format
#     report = {
#         "Vulnerabilities": vulnerabilities
#     }

#     # Save the report to a JSON file
#     with open("vulnerability_report.json", "w") as json_file:
#         json.dump(report, json_file, indent=4)

import json
import requests
from bs4 import BeautifulSoup
import re

# Define a list to store vulnerability findings
vulnerabilities = []

# Function to check for potential SQL injection
def check_sql_injection(url, text):
    sql_injection_patterns = ["SELECT * FROM", "DROP TABLE", "UNION ALL SELECT"]
    for pattern in sql_injection_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            vulnerabilities.append({
                "URL": url,
                "Vulnerability": "Potential SQL Injection",
                "Severity": "High",
                "Recommended Action": "Review and secure the SQL query."
            })

# Function to check for potential XSS (Cross-Site Scripting)
def check_xss(url, text):
    xss_patterns = ["<script>", "alert(", "onerror=", "javascript:"]
    for pattern in xss_patterns:
        if pattern in text:
            vulnerabilities.append({
                "URL": url,
                "Vulnerability": "Potential XSS (Cross-Site Scripting)",
                "Severity": "Medium",
                "Recommended Action": "Review and sanitize user inputs and output encoding."
            })

# Function to check for potential CSRF (Cross-Site REQUEST FORGERY)
def check_csrf(url, text):
    csrf_patterns = ["<form action=", "<input type=\"hidden\" name=\"csrf_token\""]
    for pattern in csrf_patterns:
        if pattern in text:
            vulnerabilities.append({
                "URL": url,
                "Vulnerability": "Cross-Site Request Forgery (CSRF)",
                "Severity": "High",
                "Recommended Action": "Implement anti-CSRF tokens and secure state-changing requests."
            })

# Function to check for potential Insecure File Upload
def check_insecure_file_upload(url, text):
    insecure_file_upload_patterns = ["<input type=\"file\"", "multipart/form-data"]
    for pattern in insecure_file_upload_patterns:
        if pattern in text:
            vulnerabilities.append({
                "URL": url,
                "Vulnerability": "Potential Insecure File Upload",
                "Severity": "Medium",
                "Recommended Action": "Implement strict validation for file uploads, store uploads in a secure location, and restrict file types."
            })

def crawl_website(url, depth):
    if depth == 0:
        return

    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            print(f"Crawling: {url}")

            # Check for vulnerabilities on the current page
            check_sql_injection(url, response.text)
            check_xss(url, response.text)
            check_csrf(url, response.text)  # Add CSRF check
            check_insecure_file_upload(url, response.text)  # Add Insecure File Upload check

            # Recursively crawl links on the current page
            for link in soup.find_all('a'):
                next_url = link.get('href')
                if next_url and next_url.startswith('http'):
                    crawl_website(next_url, depth - 1)
    except Exception as e:
        print(f"Error crawling {url}: {e}")

if __name__ == '__main__':
    start_url = 'https://www.javatpoint.com/'  # Replace with the target website
    max_depth = 1  # Maximum depth for crawling

    crawl_website(start_url, max_depth)

    # Generate a report in JSON format
    report = {
        "Vulnerabilities": vulnerabilities
    }

    # Save the report to a JSON file
    with open("vulnerability_report.json", "w") as json_file:
        json.dump(report, json_file, indent=4)
