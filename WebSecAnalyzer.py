import ssl
import socket
from datetime import datetime
import json
import dns.resolver
import whois
import requests
from requests.exceptions import RequestException as ReqExc, ConnectionError as ConnErr, Timeout as TimeoutErr
from urllib.parse import urljoin, urlparse, urlunparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from bs4 import BeautifulSoup
import time
import os
import nmap
from tabulate import tabulate
import re
from fpdf import FPDF
import random
import matplotlib.pyplot as plt
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import pyfiglet
from termcolor import colored
import subprocess
from tqdm import tqdm
import shutil

# Version information
__version__ = "1.1.0"

# Directory setup
dir_path = r"output"
os.makedirs(dir_path, exist_ok=True)
dir_path = r"graph"
os.makedirs(dir_path, exist_ok=True)
dir_path = r"raw"
os.makedirs(dir_path, exist_ok=True)

# Global variables and constants
c = datetime.now()
print(f"Starting time is {c}")
wordlist_sub_default = "wordlist/sub.txt"
wordlist_file_default = "wordlist/files.txt"
wordlist_dic_default = "wordlist/dic.txt"
all_urls_for_email_search_default = "raw/all_live_urls_for_email_search.txt"


def append_to_file(filename, content):
    """Append content to a file and create the file if it doesn't exist."""
    with open(filename, "a+", encoding="utf-8") as file:
        file.write(content + "\n")


def get_random_user_agent():
    """Returns a random User-Agent string."""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
    ]
    return random.choice(user_agents)


def get_ip_from_domain(domain):
    """Resolve a domain to its IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"[-] Could not resolve IP for domain: {domain}")
        return None


def print_heading():
    """Prints a standardized heading for tabular output."""
    tqdm.write(f"{'Path':<60} {'Status Code':<15} {'Content Length':<15} {'Word Count':<10} {'Char Count':<10} {'Message':<15}")
    tqdm.write("=" * 135)


def validate_wordlist(wordlist_path):
    """Check if the provided wordlist file path is valid."""
    if not os.path.isfile(wordlist_path):
        print(colored(f"[!] Wordlist file not found: {wordlist_path}", "red"))
        return False
    print(colored(f"[+] Wordlist found: {wordlist_path}", "green"))
    return True


def normalize_url(target_url_in):
    """
    Normalizes a URL to ensure it has a scheme (defaults to https).
    This function primarily formats, it does not validate reachability.
    """
    parsed_url = urlparse(target_url_in)
    scheme = parsed_url.scheme if parsed_url.scheme else "https"
    netloc = parsed_url.netloc if parsed_url.netloc else parsed_url.path
    if not netloc:
        return f"{scheme}://{target_url_in}"
    path = parsed_url.path if parsed_url.path else "/"
    final_url = f"{scheme}://{netloc}{path}"
    if parsed_url.query:
        final_url += "?" + parsed_url.query
    if parsed_url.fragment:
        final_url += "#" + parsed_url.fragment
    return final_url

def check_dependency(tool_name):
    """Checks if a command-line tool is installed."""
    if shutil.which(tool_name) is None:
        print(colored(f"[!] Warning: '{tool_name}' is not installed or not in PATH.", "yellow"))
        return False
    return True

def make_requester(auth_session=None):
    """
    Returns the appropriate requester (session or requests module).
    If auth_session is None, creates a new session with retry logic.
    """
    if auth_session:
        return auth_session
    else:
        # Create a new session with retry logic for unauthenticated requests
        session = requests.Session()
        # Include 429 in status_forcelist for rate-limiting retries
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({'User-Agent': get_random_user_agent()})
        return session



def extract_domain(url_or_domain):
    """Extracts the base domain (e.g., example.com) from a URL or domain string."""
    parsed = urlparse(url_or_domain)
    domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def is_potentially_authenticated(response, username_field_name, password_field_name, login_url, auth_session):
    """
    Checks if the response suggests a successful login.
    Updated heuristic based on review feedback.
    """
    response_text_lower = response.text.lower()
    final_url_lower = response.url.lower()
    login_url_lower = login_url.lower()

    # Define common error indicators
    error_indicators = [
        "invalid credentials", "login failed", "authentication failed", "login was unsuccessful",
        "incorrect username or password", "user not found", "access denied",
        "check your username", "check your password", "wrong password",
        "this field is required",
        "class=\"error\"", # Common class for error messages
        "bad username or password"
    ]
    # Check for explicit error messages first
    for indicator in error_indicators:
        if indicator in response_text_lower:
            return False, f"Login error message detected in response (found: '{indicator}')."

    # Define login form field indicators for absence check
    login_form_field_indicators = [
        f'name="{username_field_name.lower()}"', f"name='{username_field_name.lower()}'",
        f'id="{username_field_name.lower()}"', f"id='{username_field_name.lower()}'",
        f'name="{password_field_name.lower()}"', f"name='{password_field_name.lower()}'",
        f'id="{password_field_name.lower()}"', f"id='{password_field_name.lower()}'"
    ]

    # --- FIX 1: Improved Login Page Detection & Heuristic ---
    # Primary check: If redirected significantly away from login page AND session has cookies.
    # Simplified from 'response.history' to direct URL comparison as recommended.
    if response.url != login_url: # Check if the URL changed after POST
        # And the new URL does NOT contain common login/error keywords in its path/query
        if not any(kw in final_url_lower for kw in ["login", "signin", "auth", "error", "denied", "invalid", "password/reset", "failed"]):
            # And session cookies are present (strongest indicator of a persistent session)
            if auth_session and auth_session.cookies:
                # And the login form fields are NOT prominently displayed on the new page
                if not any(indicator in response_text_lower for indicator in login_form_field_indicators):
                    return True, "Redirected away from login page to a non-login/non-error page, with session cookies and no login form indicators."

    # Secondary check: If on the same URL or similar login URL, but a success keyword is present
    # AND no login form fields are present, AND session cookies exist.
    success_keywords = ["dashboard", "logout", "profile", "my account", "sign out", "welcome", "logged in as", "Welcome to the password protected area", "admin"]
    for keyword in success_keywords:
        if keyword.lower() in response_text_lower:
            if not any(indicator in response_text_lower for indicator in login_form_field_indicators):
                if auth_session and auth_session.cookies:
                    return True, f"Landed on a page with success keyword '{keyword}', no login form, and cookies are present in session."

    # Tertiary check: If session cookies are present AND no explicit error messages AND no login form fields
    if auth_session and auth_session.cookies:
        if not any(indicator in response_text_lower for indicator in error_indicators) and \
           not any(form_indicator in response_text_lower for form_indicator in login_form_field_indicators):
            return True, "Session cookies present, no error messages, and no login form indicators on final page."

    return False, "Could not confidently determine successful login based on heuristics (final URL/content/cookies)."

def _detect_and_extract_form_fields(response_text, login_url_for_action_match=None):
    """
    Detects input fields (username, password, CSRF) and form enctype from a login form.
    Returns (username_field_name, password_field_name, hidden_fields_for_csrf, form_enctype).
    If no suitable form found, returns (None, None, {}, 'application/x-www-form-urlencoded').
    """
    soup = BeautifulSoup(response_text, 'html.parser')
    forms = soup.find_all('form', method=re.compile("post", re.IGNORECASE))

    best_username_field = None
    best_password_field = None
    best_hidden_fields = {}
    best_form_enctype = "application/x-www-form-urlencoded"
    best_form_score = -1

    for form in forms:
        current_username_field = None
        current_password_field = None
        current_hidden_fields = {}
        current_form_enctype = form.get('enctype', "application/x-www-form-urlencoded")
        current_form_score = 0

        form_action = form.get('action')
        if login_url_for_action_match and form_action:
            absolute_form_action = urljoin(login_url_for_action_match, form_action)
            if absolute_form_action == login_url_for_action_match or \
               any(kw in absolute_form_action.lower() for kw in ["login", "signin", "auth"]):
                current_form_score += 10
                print(colored(f"    [Auto-Detect] Form action matches login URL or common pattern: {form_action}", "blue"))


        if "multipart/form-data" in current_form_enctype.lower():
            current_form_score += 5
            print(colored(f"    [Auto-Detect] Form enctype: {current_form_enctype}", "blue"))


        for input_tag in form.find_all('input', {'type': ['text', 'email']}):
            if input_tag.get('name') and ('user' in input_tag.get('name').lower() or 'email' in input_tag.get('name').lower()):
                current_username_field = input_tag.get('name')
                current_form_score += 3
                break
            elif input_tag.get('id') and ('user' in input_tag.get('id').lower() or 'email' in input_tag.get('id').lower()):
                current_username_field = input_tag.get('id')
                current_form_score += 2
                break
            elif input_tag.get('placeholder') and ('user' in input_tag.get('placeholder').lower() or 'email' in input_tag.get('placeholder').lower()):
                current_username_field = input_tag.get('name') or input_tag.get('id') or "username"
                current_form_score += 1
                break

        for input_tag in form.find_all('input', {'type': 'password'}):
            if input_tag.get('name') and 'pass' in input_tag.get('name').lower():
                current_password_field = input_tag.get('name')
                current_form_score += 3
                break
            elif input_tag.get('id') and 'pass' in input_tag.get('id').lower():
                current_password_field = input_tag.get('id')
                current_form_score += 2
                break
            elif input_tag.get('placeholder') and 'pass' in input_tag.get('placeholder').lower():
                current_password_field = input_tag.get('name') or input_tag.get('id') or "password"
                current_form_score += 1
                break

        for input_tag in form.find_all('input', {'type': 'hidden'}):
            if input_tag.get('name') and input_tag.get('value'):
                current_hidden_fields[input_tag.get('name')] = input_tag.get('value')
                current_form_score += 1

        if current_username_field and current_password_field and current_form_score > best_form_score:
            best_username_field = current_username_field
            best_password_field = current_password_field
            best_hidden_fields = current_hidden_fields
            best_form_enctype = current_form_enctype
            best_form_score = current_form_score
            print(colored(f"    [Auto-Detect] Found potential login form: user='{best_username_field}', pass='{best_password_field}'", "blue"))

    if best_username_field and best_password_field:
        return best_username_field, best_password_field, best_hidden_fields, best_form_enctype
    else:
        print(colored("    [Auto-Detect] Could not confidently auto-detect login form fields. Using defaults or no hidden fields.", "yellow"))
        return None, None, {}, "application/x-www-form-urlencoded"

def extract_csrf_tokens(response_text, common_csrf_names=None):
    """
    Extracts CSRF tokens from HTML content (input fields, meta tags).
    """
    if common_csrf_names is None:
        common_csrf_names = ['csrf_token', 'CSRFToken', '_csrf', 'YII_CSRF_TOKEN',
                             'csrfmiddlewaretoken', '__RequestVerificationToken', '_token', 'token']

    soup = BeautifulSoup(response_text, 'html.parser')
    tokens = {}

    for token_name_candidate in common_csrf_names:
        csrf_input = soup.find('input', {'name': token_name_candidate, 'type': 'hidden'})
        if csrf_input and csrf_input.get('value'):
            tokens[token_name_candidate] = csrf_input['value']
            print(colored(f"    Found CSRF token (hidden input): {token_name_candidate} = {tokens[token_name_candidate][:10]}...", "cyan"))

    meta_tags = soup.find_all('meta')
    for meta_tag in meta_tags:
        meta_name = meta_tag.get('name')
        meta_content = meta_tag.get('content')
        if meta_name and meta_content:
            for common_name in common_csrf_names:
                if common_name.lower() in meta_name.lower() and common_name not in tokens:
                    tokens[common_name] = meta_content
                    print(colored(f"    Found CSRF token (meta tag): {meta_name} = {tokens[common_name][:10]}...", "cyan"))
                    break

    if not tokens:
        print(colored("    No common CSRF tokens found in input fields or meta tags.", "yellow"))
    return tokens


def attempt_login(login_url, username, password, username_field="username", password_field="password",
                  login_success_keyword=None, login_debug=False, auto_csrf=False, auto_fields=False):
    """
    Attempts to log in. Includes CSRF handling, Referer header, improved success detection, and debug logging.
    Incorporates auto-field detection and dynamic Content-Type.
    """
    if not login_url:
        print(colored("[-] Login URL not provided. Skipping authenticated scan.", "red"))
        return None

    print(f"[+] Attempting login to: {login_url} as {username}")
    auth_session = requests.Session()
    # Apply retry logic to the authenticated session as well
    # Added 429 to status_forcelist for rate-limiting retries
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    auth_session.mount('http://', adapter)
    auth_session.mount('https://', adapter)

    # Pre-fetch login page to get CSRF, auto-detect fields, and Content-Type
    pre_response_text = ""
    form_enctype = "application/x-www-form-urlencoded" # Default Content-Type
    detected_hidden_fields = {} # For auto-detected CSRF/hidden fields
    actual_username_field = username_field # Use provided or auto-detected
    actual_password_field = password_field # Use provided or auto-detected


    print(colored("    Fetching login page for pre-analysis (fields, CSRF, enctype)...", "blue"))
    try:
        pre_response = auth_session.get(login_url, timeout=10, allow_redirects=True, verify=False)
        if pre_response.status_code == 200:
            pre_response_text = pre_response.text

            # --- Auto Field Detection ---
            if auto_fields:
                print(colored("    Attempting to auto-detect login form fields and enctype...", "blue"))
                detected_user_field, detected_pass_field, detected_hidden_fields_temp, detected_enctype = \
                    _detect_and_extract_form_fields(pre_response_text, login_url)

                if detected_user_field:
                    actual_username_field = detected_user_field
                if detected_pass_field:
                    actual_password_field = detected_pass_field

                form_enctype = detected_enctype # Update Content-Type from detected enctype
                detected_hidden_fields.update(detected_hidden_fields_temp) # Add other detected hidden fields

            # --- Auto CSRF Token Fetching (now also from meta tags) ---
            if auto_csrf:
                print(colored("    Attempting to fetch CSRF token...", "blue"))
                csrf_tokens_from_page = extract_csrf_tokens(pre_response_text)
                detected_hidden_fields.update(csrf_tokens_from_page) # Merge with any auto-detected hidden fields

        else:
            print(colored(f"    Failed to GET login page for pre-analysis (Status: {pre_response.status_code}). Proceeding without dynamic detection.", "yellow"))

    except ReqExc as e:
        print(colored(f"    Error fetching login page for pre-analysis: {e}. Proceeding with default field names/headers.", "yellow"))


    # Set up headers for the POST request
    auth_session.headers.update({
        'User-Agent': get_random_user_agent(),
        'Referer': login_url,
        'Origin': urlparse(login_url).scheme + "://" + urlparse(login_url).netloc,
        'Content-Type': form_enctype # Use dynamically detected enctype
    })

    payload = {
        actual_username_field: username,
        actual_password_field: password
    }
    payload.update(detected_hidden_fields) # Add all detected hidden fields (including CSRF) to payload

    if login_debug:
        print(colored("\n--- Login Debug Information ---", "yellow"))
        print(colored(f"[DEBUG] Login URL: {login_url}", "yellow"))
        print(colored(f"[DEBUG] Username: {username}", "yellow"))
        print(colored(f"[DEBUG] Password: {'*' * len(password)} (Masked)", "yellow"))
        print(colored(f"[DEBUG] Username Field Name: {actual_username_field} (Final)", "yellow"))
        print(colored(f"[DEBUG] Password Field Name: {actual_password_field} (Final)", "yellow"))
        print(colored(f"[DEBUG] Content-Type for POST: {form_enctype}", "yellow"))
        print(colored(f"[DEBUG] Request Headers Sent (subset): { {k: v for k, v in auth_session.headers.items() if k in ['User-Agent', 'Referer', 'Origin', 'Content-Type']} }", "yellow"))
        print(colored(f"[DEBUG] POST Payload (with detected hidden fields/CSRF): {payload}", "yellow"))
        print(colored("-------------------------------", "yellow"))


    response_after_post = None
    try:
        response_after_post = auth_session.post(login_url, data=payload, timeout=25, allow_redirects=True, verify=False)

        if login_debug:
            print(colored(f"[DEBUG] Response Status Code: {response_after_post.status_code}", "yellow"))
            print(colored(f"[DEBUG] Response URL (final): {response_after_post.url}", "yellow"))
            if response_after_post.history:
                for i, resp_hist in enumerate(response_after_post.history):
                    print(colored(f"[DEBUG]   Redirect {i+1}: {resp_hist.status_code} -> {resp_hist.url} (Cookies: {resp_hist.cookies.get_dict()})", "yellow"))
            else:
                print(colored("[DEBUG]   No redirects in history.", "yellow"))
            print(colored(f"[DEBUG] Final Response Cookies (Set by server in this response): {response_after_post.cookies.get_dict()}", "yellow"))
            print(colored(f"[DEBUG] Session Cookies (After request): {auth_session.cookies.get_dict()}", "yellow"))
            print(colored("--- End Login Debug ---", "yellow"))

        # Priority 1: User-defined success keyword
        keyword_found_in_response = False
        if login_success_keyword:
            if login_success_keyword.lower() in response_after_post.text.lower():
                print(colored(f"[+] Login successful! User-defined success keyword '{login_success_keyword}' found.", "green"))
                auth_log_file = "raw/authenticated_session_log.txt"
                log_content = f"--- Login Success (Form - Keyword) at {datetime.now()} ---\n"
                log_content += f"Login URL: {login_url}\nUsername: {username}\nKeyword: {login_success_keyword}\n"
                log_content += f"Session Cookies: {json.dumps(auth_session.cookies.get_dict(), indent=2)}\n\n"
                append_to_file(auth_log_file, log_content)
                keyword_found_in_response = True
                return auth_session

        # Priority 2: Heuristic check (only if keyword wasn't provided or wasn't found)
        is_auth, reason = is_potentially_authenticated(response_after_post, actual_username_field, actual_password_field, login_url, auth_session)

        if is_auth:
            if auth_session.cookies:
                print(colored(f"[+] Login likely successful. Reason: {reason}", "green"))
                cookie_dict = auth_session.cookies.get_dict()
                print(colored(f"    Session cookies obtained: {cookie_dict}", "cyan"))
                auth_log_file = "raw/authenticated_session_log.txt"
                log_content = f"--- Login Success (Form - Heuristic) at {datetime.now()} ---\n"
                log_content += f"Login URL: {login_url}\nUsername: {username}\nReason: {reason}\n"
                log_content += f"Session Cookies: {json.dumps(cookie_dict, indent=2)}\n\n"
                append_to_file(auth_log_file, log_content)
                return auth_session
            else:
                print(colored(f"[-] Login attempt heuristically seemed successful ({reason}), but no session cookies were persisted.", "yellow"))
                reason = f"Heuristic success but no session cookies ({reason})."

        # If neither keyword (if provided) nor heuristic confirmed login, it's a failure.
        final_failure_reason = reason
        if login_success_keyword and not keyword_found_in_response:
             final_failure_reason = f"User-defined keyword '{login_success_keyword}' not found, and heuristic was inconclusive or overridden: {reason}"
        elif not is_auth:
             final_failure_reason = reason

        print(colored(f"[-] Login failed or success could not be determined. Final Reason: {final_failure_reason}", "red"))
        if response_after_post is not None:
            debug_log_path = "raw/login_debug_dump.txt"
            print(colored(f"[DEBUG] Final check failed. Final URL: {response_after_post.url}, Status: {response_after_post.status_code}", "red"))
            dump_content = f"--- Login Attempt Debug Dump (Overall Fail) for {login_url} at {datetime.now()} ---\n"
            dump_content += f"Username: {username}\nFinal URL: {response_after_post.url}\nStatus Code: {response_after_post.status_code}\n"
            dump_content += f"Final Reason Determined: {final_failure_reason}\n\n--- Response Headers ---\n"
            for k, v_ in response_after_post.headers.items(): dump_content += f"{k}: {v_}\n"
            dump_content += "\n--- Response Body (First 2000 Chars) ---\n" + response_after_post.text[:2000] + "\n"
            dump_content += "\n--- Session Cookies After Attempt ---\n"
            dump_content += json.dumps(auth_session.cookies.get_dict(), indent=4) + "\n" if auth_session.cookies else "No session cookies.\n"
            with open(debug_log_path, "w", encoding="utf-8") as f_debug_dump: f_debug_dump.write(dump_content)
            print(colored(f"[DEBUG] Detailed response logged to {debug_log_path}", "red"))
        return None

    except TimeoutErr:
        print(colored(f"[-] Login request to {login_url} timed out.", "red"))
        if login_debug: print(colored("[DEBUG] Request Timed Out.", "red"))
        return None
    except ConnErr:
        print(colored(f"[-] Login request to {login_url} failed (Connection Error).", "red"))
        if login_debug: print(colored("[DEBUG] Connection Error.", "red"))
        return None
    except ReqExc as e:
        print(colored(f"[-] Login request to {login_url} failed: {e}", "red"))
        if login_debug: print(colored(f"[DEBUG] Generic Request Exception: {e}", "red"))
        return None

# --- Reconnaissance Functions ---
def whois_lookup(domain_to_check):
    """Perform a WHOIS lookup."""
    filename = "raw/whois_info.txt"
    file_out = "output/1_whois_info.txt"
    print(f"[+] Performing WHOIS lookup for: {domain_to_check}")
    try:
        w = whois.whois(domain_to_check)
        if w and w.text:
            whois_data = f"\n--- WHOIS Data for {domain_to_check} (Timestamp: {c}) ---\n{w.text}"
            append_to_file(filename, whois_data)
            append_to_file(file_out, whois_data)
            print(colored(f"    WHOIS data saved to {filename} and {file_out}", "blue"))
            return w
        else:
            msg = f"--- No WHOIS data found or an issue with the response for {domain_to_check} ---"
            append_to_file(filename, msg)
            append_to_file(file_out, msg)
            print(colored(f"    {msg}", "yellow"))
            return None
    except Exception as e:
        error_msg = f"--- WHOIS lookup failed for {domain_to_check}: {e} ---"
        append_to_file(filename, error_msg)
        append_to_file(file_out, error_msg)
        print(colored(f"    {error_msg}", "red"))
        return None

def dns_lookup(domain_to_check):
    """Perform a DNS lookup for A records."""
    file_out = "output/2_dns_lookup.txt"
    filename = "raw/dns_lookup.txt"
    print(f"[+] Performing DNS lookup for: {domain_to_check}")
    try:
        result = dns.resolver.resolve(domain_to_check, 'A')
        ips = [ip.to_text() for ip in result]
        output = f"--- DNS Lookup Results for {domain_to_check} ---\nIP Addresses: {', '.join(ips)}"
        append_to_file(filename, output)
        append_to_file(file_out, output)
        print(colored(f"    DNS records: {', '.join(ips)}", "blue"))
        return ips
    except Exception as e:
        error_msg = f"DNS lookup failed for {domain_to_check}: {e}"
        append_to_file(filename, error_msg)
        append_to_file(file_out, error_msg)
        print(colored(f"    {error_msg}", "red"))
        return None

def ssl_info_checker(domain_to_check):
    """Fetch SSL certificate information."""
    filename = "raw/ssl_info.txt"
    file_out = "output/3_ssl_info.txt"
    ssl_info_data = {}
    print(f"[+] Checking SSL certificate for: {domain_to_check}")
    try:
        # Use `socket.gethostbyname` to resolve domain to IP for connection
        ip_address = get_ip_from_domain(domain_to_check)
        if not ip_address:
            raise ValueError(f"Could not resolve IP for {domain_to_check}")

        context = ssl.create_default_context()
        # Connect to IP address, but specify domain for server_hostname in TLS handshake
        with socket.create_connection((ip_address, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain_to_check) as ssock:
                cert = ssock.getpeercert()
                ssl_info_data['subject'] = dict(x[0] for x in cert.get('subject', []))
                ssl_info_data['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                ssl_info_data['serial_number'] = cert.get('serialNumber', 'N/A')
                valid_from_str = cert.get('notBefore')
                valid_to_str = cert.get('notAfter')

                if valid_from_str:
                    ssl_info_data['valid_from'] = datetime.strptime(valid_from_str, '%b %d %H:%M:%S %Y %Z')
                else:
                    ssl_info_data['valid_from'] = 'N/A'

                if valid_to_str:
                    ssl_info_data['valid_to'] = datetime.strptime(valid_to_str, '%b %d %H:%M:%S %Y %Z')
                    if isinstance(ssl_info_data['valid_to'], datetime):
                        ssl_info_data['is_valid'] = datetime.now() < ssl_info_data['valid_to']
                    else:
                        ssl_info_data['is_valid'] = 'Unknown'
                else:
                    ssl_info_data['valid_to'] = 'N/A'
                    ssl_info_data['is_valid'] = 'Unknown'

                output = json.dumps(ssl_info_data, indent=4, default=str)
                full_output = f"--- SSL Certificate Information for {domain_to_check} ---\n{output}"
                append_to_file(filename, full_output)
                append_to_file(file_out, full_output)
                print(colored(f"    SSL info saved.", "blue"))
                return ssl_info_data
    except Exception as e:
        error_msg = f"Failed to retrieve SSL information for {domain_to_check}: {e}"
        append_to_file(filename, error_msg)
        append_to_file(file_out, error_msg)
        print(colored(f"    {error_msg}", "red"))
        return None

def crtsh_lookup(domain_to_check):
    """Retrieve certificate transparency logs from crt.sh."""
    filename = "raw/crtsh_info.txt"
    file_out = "output/4_crtsh_info.txt"
    url = f"https://crt.sh/?q=%.{domain_to_check}&output=json"
    print(f"[+] Performing crt.sh lookup for: {domain_to_check}")
    try:
        response = requests.get(url, timeout=10, verify=False)
        response.raise_for_status()
        crt_data = response.json()
        if crt_data:
            output_str = f"--- Certificate Transparency Logs for {domain_to_check} ---\n"
            log_entries = []
            for entry in crt_data:
                log_entries.append(
                    f"  Issuer: {entry.get('issuer_name', 'N/A')}\n"
                    f"  Common Name: {entry.get('common_name', 'N/A')}\n"
                    f"  Not Before: {entry.get('not_before', 'N/A')}\n"
                    f"  Not After: {entry.get('not_after', 'N/A')}\n"
                    f"  Identity: {entry.get('name_value', 'N/A')}\n"
                )
            output_str += "\n".join(log_entries)
            append_to_file(filename, output_str)
            append_to_file(file_out, output_str)
            print(colored(f"    crt.sh data saved.", "blue"))
            return crt_data
        else:
            msg = f"No crt.sh data found for {domain_to_check}"
            append_to_file(filename, msg)
            append_to_file(file_out, msg)
            print(colored(f"    {msg}", "yellow"))
            return None
    except Exception as e:
        error_msg = f"crt.sh lookup failed for {domain_to_check}: {e}"
        append_to_file(filename, error_msg)
        append_to_file(file_out, error_msg)
        print(colored(f"    {error_msg}", "red"))
        return None


# Helper function to process a single URL for enumeration
def _process_single_url(url_item, requester, file_200, file_403, output_summary_file):
    """Helper function to fetch a single URL and process its response."""
    # User-Agent is already handled by make_requester when session is created/returned
    try:
        # Use a higher timeout for enumeration to account for network latency or slow servers
        # Removed explicit 'headers' arg as it's handled by requester's default_headers
        response = requester.get(url_item, timeout=10, allow_redirects=False, verify=False)
        content_length = len(response.content)
        word_count = len(response.text.split())
        char_count = len(response.text)
        status_msg = f"{response.status_code} {response.reason}"

        if response.status_code == 200:
            append_to_file(file_200, url_item)
            append_to_file(output_summary_file, f"[FOUND 200] {url_item}")
            msg_display = "200 OK"
        elif response.status_code == 403:
            append_to_file(file_403, url_item)
            append_to_file(output_summary_file, f"[FOUND 403] {url_item}")
            msg_display = "403 Forbidden"
        else:
            msg_display = status_msg

        tqdm.write(f"{url_item:<60} {response.status_code:<15} {content_length:<15} {word_count:<10} {char_count:<10} {msg_display:<15}")

    except ReqExc:
        tqdm.write(f"{url_item:<60} {'N/A':<15} {'N/A':<15} {'N/A':<10} {'N/A':<10} {'Connection Error':<15}")
    finally: # Add small random delay after each request to mitigate rate-limiting
        time.sleep(random.uniform(0.1, 0.5))


# --- Enumeration Functions (Session-Aware & Multithreaded) ---
def subdomain_bruteforce(base_domain, wordlist_path, auth_session=None, max_workers=20):
    """Brute-force subdomains using a wordlist."""
    print(f"[+] Starting subdomain bruteforce for: {base_domain} using {wordlist_path}")
    print_heading()

    file_200 = "raw/sub_brute_domains_200.txt"
    file_403 = "raw/sub_brute_domains_403.txt"
    output_summary_file = "output/5_subdomain_bruteforce.txt"

    # Clear previous results for this run
    open(file_200, 'w').close()
    open(file_403, 'w').close()
    open(output_summary_file, 'w').close()

    if not validate_wordlist(wordlist_path): return

    with open(wordlist_path, 'r', encoding='utf-8') as file:
        subdomains = [line.strip() for line in file if line.strip()]

    # Construct URLs using the resolved base_domain which now correctly includes scheme
    urls_to_check = [f"{base_domain.split('://')[0]}://{sub}.{extract_domain(base_domain)}" for sub in subdomains]

    # make_requester ensures we get a session with retry logic,
    # or the provided authenticated_session if available.
    requester = make_requester(auth_session)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # map() returns results in the order the tasks were submitted
        list(tqdm(executor.map(lambda url: _process_single_url(url, requester, file_200, file_403, output_summary_file), urls_to_check), total=len(urls_to_check), desc="Subdomains", leave=False))

def enumerate_paths_generic(base_url_to_scan, wordlist_path, output_file_prefix, summary_file_id, auth_session=None, max_workers=20):
    """Generic path enumeration function for directories or files."""
    print(f"[+] Starting {output_file_prefix} enumeration for: {base_url_to_scan} using {wordlist_path}")
    print_heading()

    file_200 = f"raw/{output_file_prefix}_brute_200.txt"
    file_403 = f"raw/{output_file_prefix}_brute_403.txt"
    output_summary_file = f"output/{summary_file_id}_{output_file_prefix}_bruteforce.txt"

    # Clear previous results for this run
    open(file_200, 'w').close()
    open(file_403, 'w').close()
    open(output_summary_file, 'w').close()

    processed_base_url = base_url_to_scan # This is already the validated URL with scheme
    if not processed_base_url.endswith('/'):
        processed_base_url += '/'

    if not validate_wordlist(wordlist_path): return

    with open(wordlist_path, 'r', encoding='utf-8') as file:
        paths = [line.strip() for line in file if line.strip()]

    urls_to_check = [urljoin(processed_base_url, path_item.lstrip('/')) for path_item in paths]

    requester = make_requester(auth_session)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(tqdm(executor.map(lambda url: _process_single_url(url, requester, file_200, file_403, output_summary_file), urls_to_check), total=len(urls_to_check), desc=f"{output_file_prefix.title()}", leave=False))


def enumerate_combined_paths(base_url_to_scan, dir_wordlist_path, file_wordlist_path, auth_session=None, max_workers=20):
    """Enumerates combined directory/file paths."""
    print(f"[+] Starting combined path enumeration for: {base_url_to_scan}")
    print_heading()

    file_200 = "raw/combined_path_brute_200.txt"
    file_403 = "raw/combined_path_brute_403.txt"
    output_summary_file = "output/X_combined_paths.txt"

    # Clear previous results for this run
    open(file_200, 'w').close()
    open(file_403, 'w').close()
    open(output_summary_file, 'w').close()

    processed_base_url = base_url_to_scan # This is already the validated URL with scheme
    if not processed_base_url.endswith('/'):
        processed_base_url += '/'

    if not validate_wordlist(dir_wordlist_path) or not validate_wordlist(file_wordlist_path): return

    with open(dir_wordlist_path, 'r', encoding='utf-8') as d_file:
        directories = [d.strip() for d in d_file if d.strip()]
    with open(file_wordlist_path, 'r', encoding='utf-8') as f_file:
        files = [f.strip() for f in f_file if f.strip()]

    urls_to_check = []
    for directory in directories:
        for file_item in files:
            path_segment = f"{directory.strip('/')}/{file_item.strip('/')}"
            urls_to_check.append(urljoin(processed_base_url, path_segment))

    requester = make_requester(auth_session)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(tqdm(executor.map(lambda url: _process_single_url(url, requester, file_200, file_403, output_summary_file), urls_to_check), total=len(urls_to_check), desc="Combined Paths", leave=False))


visited_links_crawler = set()
def crawler(start_url, max_depth=2, auth_session=None):
    """Recursively crawls a domain to find links."""
    global visited_links_crawler
    # Reset visited_links_crawler for each new crawl, if desired for multiple crawl calls
    # For a single main crawl, this clear is fine.
    # visited_links_crawler.clear()

    output_file = "raw/crawler_output.txt"
    summary_file = "output/Y_crawler_summary.txt"
    open(output_file, 'w').close()
    open(summary_file, 'w').close()

    current_start_url = start_url # This is already the validated URL with scheme
    parsed_start_url = urlparse(current_start_url)

    base_domain_netloc = parsed_start_url.netloc
    requester = make_requester(auth_session)

    print(f"[+] Starting crawler on {current_start_url} (max depth: {max_depth})")
    pbar = tqdm(desc="Crawling", unit="url", leave=False)

    def fetch_links_recursive(current_url_to_crawl, current_depth):
        global visited_links_crawler
        if current_depth > max_depth or current_url_to_crawl in visited_links_crawler:
            return

        visited_links_crawler.add(current_url_to_crawl)
        # User-Agent is already handled by make_requester
        try:
            response = requester.get(current_url_to_crawl, timeout=7, allow_redirects=True, verify=False)
            actual_crawled_url = response.url
            if response.status_code != 200:
                print(f"    Skipping {actual_crawled_url}, status code: {response.status_code}")
                return
        except TimeoutErr:
            print(f"    Timeout accessing {current_url_to_crawl}")
            return
        except ConnErr:
            print(f"    Connection error for {current_url_to_crawl}")
            return
        except ReqExc as e:
            print(f"    Error accessing {current_url_to_crawl}: {e}")
            return
        finally: # Add small random delay after each request to mitigate rate-limiting
            time.sleep(random.uniform(0.1, 0.5))

        tqdm.write(f"    Crawling (Depth {current_depth}): {actual_crawled_url}")
        append_to_file(output_file, actual_crawled_url)
        pbar.update(1)

        soup = BeautifulSoup(response.text, 'html.parser')
        page_links = set()
        for link_tag in soup.find_all('a', href=True):
            href_val = link_tag['href']
            if not href_val or href_val.startswith("mailto:") or href_val.startswith("tel:") or href_val.startswith("javascript:"):
                continue
            absolute_url = urljoin(actual_crawled_url, href_val)
            parsed_abs_url = urlparse(absolute_url)

            if parsed_abs_url.netloc == base_domain_netloc and parsed_abs_url.scheme in ['http', 'https']:
                cleaned_url = parsed_abs_url._replace(fragment="").geturl()
                if cleaned_url not in visited_links_crawler:
                    page_links.add(cleaned_url)

        for found_link in page_links:
            fetch_links_recursive(found_link, current_depth + 1)

    fetch_links_recursive(current_start_url, 1)
    pbar.close()
    append_to_file(summary_file, f"Crawler finished. Found {len(visited_links_crawler)} unique links. Stored in {output_file}")
    print(f"[+] Crawler finished. Results in {output_file}")


def filter_urls(input_file_path="raw/crawler_output.txt", output_file_path="raw/filtered_urls.txt"):
    """Filters URLs, removing common non-HTML file extensions."""
    print(f"[+] Filtering URLs from {input_file_path}")
    unwanted_extensions = {
        ".png", ".jpg", ".jpeg", ".svg", ".gif", ".bmp", ".ico", ".tif", ".tiff", ".webp",
        ".mp4", ".avi", ".mov", ".mkv", ".flv", ".wmv", ".webm", ".m4v",
        ".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a",
        ".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".odt"
        , ".rar", ".tar", ".gz", ".7z", ".bz2", ".xz", ".iso",
        ".exe", ".dll", ".bin", ".dmg", ".apk", ".msi", ".deb", ".rpm",
        ".ttf", ".otf", ".woff", ".woff2", ".eot",
        ".css", ".js", ".json", ".xml", ".csv",
        ".txt", ".md", ".tmp", ".swf", ".map"
    }

    filtered_url_list = []
    graph_file_path = "graph/filtered_urls_count.txt"

    open(output_file_path, 'w').close()
    open(graph_file_path, 'w').close()

    try:
        with open(input_file_path, "r", encoding="utf-8") as file:
            for line in file:
                url = line.strip()
                if not url: continue
                parsed_url = urlparse(url)
                path_lower = parsed_url.path.lower()
                if not any(path_lower.endswith(ext) for ext in unwanted_extensions):
                    append_to_file(output_file_path, url)
                    append_to_file(graph_file_path, url)
                    filtered_url_list.append(url)
        print(f"    Filtered URLs saved to {output_file_path}")
    except FileNotFoundError:
        print(f"    Error: File '{input_file_path}' not found for filtering.")
    return filtered_url_list

def gather_discovered_urls(output_file=all_urls_for_email_search_default):
    """Gathers all unique 200 OK URLs from various raw files into a single file."""
    print(f"[+] Gathering all discovered live URLs for further processing...")
    source_files = [
        "raw/sub_brute_domains_200.txt",
        "raw/directory_brute_200.txt",
        "raw/file_brute_200.txt",
        "raw/combined_path_brute_200.txt",
        "raw/crawler_output.txt",
        "graph/httpx_200_output.txt"
    ]
    all_urls = set()
    for s_file in source_files:
        if os.path.exists(s_file):
            try:
                with open(s_file, "r", encoding="utf-8") as f:
                    for line in f:
                        stripped_line = line.strip()
                        if stripped_line and (stripped_line.startswith("http://") or stripped_line.startswith("https://")):
                            all_urls.add(stripped_line)
            except Exception as e:
                print(colored(f"    Error reading from {s_file}: {e}", "yellow"))

    if all_urls:
        with open(output_file, "w", encoding="utf-8") as f_out:
            for url_item in sorted(list(all_urls)):
                f_out.write(url_item + "\n")
        print(colored(f"    Found {len(all_urls)} unique URLs. Saved to {output_file}", "green"))
    else:
        print(colored("    No URLs gathered from source files for email search.", "yellow"))
    return output_file


def find_emails(url_list_file, auth_session=None):
    """Extracts email addresses from a list of URLs."""
    print(f"[+] Searching for emails in URLs from: {url_list_file}")
    output_temp_emails = "raw/all_founded_temp_emails.txt"
    open(output_temp_emails, 'w').close()

    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    requester = make_requester(auth_session)

    if not os.path.exists(url_list_file):
        print(colored(f"    URL list file for email search not found: {url_list_file}. Skipping email search.", "yellow"))
        return

    try:
        with open(url_list_file, "r", encoding='utf-8') as file:
            urls_to_scan = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(colored(f"    File not found: {url_list_file}", "red"))
        return

    if not urls_to_scan:
        print(colored(f"    No URLs to scan for emails in {url_list_file}.", "yellow"))
        return

    for url in tqdm(urls_to_scan, desc="Email Search", unit="url", leave=False):
        tqdm.write(f"    Processing for emails: {url}")
        # User-Agent is already handled by make_requester
        try:
            response = requester.get(url, timeout=7, allow_redirects=True, verify=False)
            found_emails_on_page = set(re.findall(email_pattern, response.text))
            if found_emails_on_page:
                for email in found_emails_on_page:
                    append_to_file(output_temp_emails, email)
                    tqdm.write(colored(f"        Found email: {email}", "green"))
        except ReqExc as e:
            print(colored(f"        Failed to access {url} for email search: {e}", "yellow"))
        finally: # Add small random delay after each request to mitigate rate-limiting
            time.sleep(random.uniform(0.1, 0.5))


def clean_and_sort_emails(temp_email_file="raw/all_founded_temp_emails.txt",
                          final_email_file="raw/all_founded_final_emails.txt",
                          summary_file="output/6_emails_found.txt",
                          domain_scope=None):
    """Cleans, sorts, and optionally filters emails by domain."""
    print(f"[+] Cleaning and sorting emails from {temp_email_file}")
    open(final_email_file, 'w').close()
    open(summary_file, 'w').close()

    if not os.path.exists(temp_email_file):
        print(colored(f"    Temporary email file '{temp_email_file}' not found. Skipping cleaning.", "yellow"))
        append_to_file(summary_file, f"\n--- Unique Emails Found ({datetime.now()}) ---\nNo emails found to process.")
        return

    try:
        with open(temp_email_file, "r", encoding='utf-8') as file:
            emails = {line.strip().lower() for line in file if "@" in line and "." in line.split('@')[-1]}

        if domain_scope:
            clean_domain_scope = extract_domain(domain_scope)
            emails = {email for email in emails if email.endswith(f"@{clean_domain_scope}")}

        sorted_emails = sorted(list(emails))

        summary_header = f"\n--- Unique Emails Found ({datetime.now()}) ---\n"
        if domain_scope:
            summary_header = f"\n--- Unique Emails Found for domain scope '{extract_domain(domain_scope)}' ({datetime.now()}) ---\n"

        append_to_file(summary_file, summary_header)

        if sorted_emails:
            for email in sorted_emails:
                append_to_file(final_email_file, email)
                append_to_file(summary_file, email)
            print(colored(f"    Process completed! Cleaned emails ({len(sorted_emails)}) saved to {final_email_file} and {summary_file}.", "blue"))
        else:
            print(colored("    No emails found after cleaning/filtering.", "yellow"))
            append_to_file(summary_file, "No emails found.")

    except FileNotFoundError:
        print(colored(f"    Error: Temp email file '{temp_email_file}' not found.", "red"))
    except Exception as e:
        print(colored(f"    An error occurred during email cleaning: {e}", "red"))


def make_request_for_bypass(url, headers_to_try, auth_session=None):
    """Makes a request for 403 bypass, potentially using an authenticated session."""
    requester = make_requester(auth_session)
    try:
        final_headers = {}
        if auth_session:
            final_headers.update(auth_session.headers)
        final_headers.update(headers_to_try)

        response = requester.get(url, headers=final_headers, timeout=5, allow_redirects=False, verify=False)
        return response.status_code, response.text
    except ReqExc:
        return None, None
    finally: # Add small random delay after each request to mitigate rate-limiting
        time.sleep(random.uniform(0.1, 0.5))


def bypass_403(url_to_check, auth_session=None):
    """Attempts to bypass 403 Forbidden errors using various headers."""
    print(f"[+] Attempting 403 bypass for: {url_to_check}")
    output_bypassed_file = "raw/403_bypass_successful.txt"
    graph_bypassed_file = "graph/403_bypass_successful_count.txt"

    headers_payloads = [
        {"X-Original-URL": "/"}, {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"}, {"X-Forwarded-Host": "localhost"},
        {"X-HTTP-Method-Override": "GET"}, {"X-Rewrite-URL": "/"},
        {"Referer": urlparse(url_to_check)._replace(path="", query="", fragment="").geturl()},
        {"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"},
        {"X-Forwarded-For": "8.8.8.8"}, {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"}, {"X-Client-IP": "127.0.0.1"},
        {"X-Host": "127.0.0.1"}, {"X-Originating-IP": "127.0.0.1"},
    ]

    for headers_to_try in tqdm(headers_payloads, desc="Bypassing 403", leave=False):
        status_code, _ = make_request_for_bypass(url_to_check, headers_to_try, auth_session)

        if status_code and 200 <= status_code < 300:
            payload_str = ", ".join([f"{k}: {v}" for k, v in headers_to_try.items()])
            success_msg = f"[BYPASS SUCCESSFUL] URL: {url_to_check} | Payload: [{payload_str}] | Status: {status_code}"
            print(colored(f"\n{success_msg}", "green"))
            append_to_file(output_bypassed_file, success_msg)
            append_to_file(graph_bypassed_file, url_to_check)
            return

    # print(f"    No header-based bypass found for {url_to_check} with these techniques.")


# --- Nmap Scanning ---
def format_nmap_results(nm_scanner, ip_address):
    """Formats Nmap scan results into a readable string."""
    results_list = []
    if ip_address not in nm_scanner.all_hosts():
        return f"Nmap scan did not find the host '{ip_address}' or an error occurred."

    host_data = nm_scanner[ip_address]
    for proto in host_data.all_protocols():
        ports = host_data[proto].keys()
        for port in ports:
            port_info = host_data[proto][port]
            results_list.append([
                proto, port,
                port_info.get('name', 'N/A'),
                port_info.get('product', 'N/A'),
                port_info.get('version', 'N/A'),
                port_info.get('state', 'N/A')
            ])

    os_match_list = host_data.get('osmatch', [])
    os_info = "OS Not Detected"
    if os_match_list:
        best_os_match = max(os_match_list, key=lambda x: int(x.get('accuracy', '0')), default=None)
        if best_os_match:
            os_info = best_os_match.get('name', 'N/A')

    headers = ["Protocol", "Port", "Service", "Product", "Version", "State"]
    port_table = tabulate(results_list, headers, tablefmt="grid")
    return f"OS Detection: {os_info}\n\nPort Scan Results:\n{port_table}"

def run_nmap_scan(target_ip, arguments, scan_name, output_file_id):
    """Runs a generic Nmap scan."""
    if not target_ip:
        print(colored(f"[-] Nmap {scan_name}: IP address is None, skipping scan.", "red"))
        return

    if not check_dependency("nmap"):
        print(colored(f"[-] Nmap {scan_name}: Nmap binary not found. Skipping scan.", "red"))
        return

    summary_output_file = f"output/{output_file_id}_nmap_{scan_name.lower().replace(' ', '_')}.txt"
    open(summary_output_file, 'w').close()

    print(f"[+] Running Nmap {scan_name} on {target_ip} (Args: {arguments})...")
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target_ip, arguments=arguments)

        if nm.all_hosts() and target_ip in nm.all_hosts():
            scan_results_formatted = format_nmap_results(nm, target_ip)
            final_output = f"--- Nmap {scan_name} Results for {target_ip} ---\n{scan_results_formatted}"
            append_to_file(summary_output_file, final_output)
            print(colored(f"    Nmap {scan_name} results saved to {summary_output_file}", "blue"))
        else:
            msg = f"Nmap {scan_name} did not return results for {target_ip} or host was down."
            print(colored(f"    {msg}", "yellow"))
            append_to_file(summary_output_file, msg)
            if nm.scaninfo() and 'error' in nm.scaninfo():
                 append_to_file(summary_output_file, f"Scan Info Error: {nm.scaninfo()['error']}")

    except nmap.PortScannerError as e:
        error_msg = f"Nmap {scan_name} PortScannerError for {target_ip}: {e}. Ensure Nmap is installed and in PATH."
        print(colored(f"    {error_msg}", "red"))
        append_to_file(summary_output_file, error_msg)
    except Exception as e:
        error_msg = f"An unexpected error occurred during Nmap {scan_name} for {target_ip}: {e}"
        print(colored(f"    {error_msg}", "red"))
        append_to_file(summary_output_file, error_msg)


# --- Reporting ---
def generate_graph(graph_dir="graph", output_image_file="scan_summary_graph.png"):
    """Generates a bar graph of URL counts by category."""
    print("[+] Generating summary graph...")
    file_map = {
        "httpx_200_output.txt": "200 OK (HTTPX)",
        "httpx_403_output.txt": "403 Forbidden (HTTPX)",
        "filtered_urls_count.txt": "Crawler - Filtered Links",
        "403_bypass_successful_count.txt": "403 Bypassed",
        "sub_brute_domains_200.txt": "Subdomain Brute (200)",
        "directory_brute_200.txt": "Directory Brute (200)",
        "file_brute_200.txt": "File Brute (200)",
    }
    data_counts = {}

    os.makedirs(graph_dir, exist_ok=True)

    for file_name, label in file_map.items():
        if file_name.endswith("_count.txt"):
            file_path_to_count = os.path.join(graph_dir, file_name)
        else:
            if "httpx" in file_name:
                 file_path_to_count = os.path.join(graph_dir, file_name)
            else:
                 file_path_to_count = os.path.join("raw", file_name)

        try:
            if not os.path.exists(file_path_to_count):
                if "HTTPX" in label and not sys.platform.startswith("linux"):
                    print(f"    Graph data source file for HTTPX not found (expected as script is not on Linux or tool not run): {file_path_to_count}")
                elif "HTTPX" in label:
                     print(f"    Graph data source file for HTTPX not found (tool might have failed): {file_path_to_count}")
                else:
                    print(f"    Graph data source file not found, skipping: {file_path_to_count}")
                data_counts[label] = 0
                continue
            with open(file_path_to_count, "r", encoding="utf-8") as file:
                count = sum(1 for line in file if line.strip())
            data_counts[label] = count
        except Exception as e:
            print(f"    Error reading graph data file {file_path_to_count}: {e}")
            data_counts[label] = 0

    if not any(data_counts.values()):
        print(colored("    No data found for graph generation. Skipping.", "yellow"))
        return False

    categories = list(data_counts.keys())
    counts = list(data_counts.values())

    plt.figure(figsize=(14, 8))
    bar_colors = ['skyblue', 'lightcoral', 'lightgreen', 'gold', 'plum', 'lightsalmon', 'lightblue', 'lightpink']
    bars = plt.bar(categories, counts, color=bar_colors[:len(categories)])
    plt.title("Scan Summary: URL Counts by Category", fontsize=16)
    plt.xlabel("Categories", fontsize=12)
    plt.ylabel("Number of URLs/Items", fontsize=12)
    plt.xticks(rotation=45, ha="right", fontsize=9)
    plt.yticks(fontsize=10)
    plt.tight_layout()

    for bar in bars:
        yval = bar.get_height()
        if yval > 0:
            plt.text(bar.get_x() + bar.get_width()/2.0, yval + 0.01 * max(counts, default=1), int(yval), ha='center', va='bottom', fontsize=9)

    plt.savefig(output_image_file)
    plt.close()
    print(colored(f"    Graph saved as {output_image_file}", "green"))
    return True


def generate_pdf_report(report_filename="WebSecAnalyzer_Report.pdf", output_dir="output", graph_image_path="scan_summary_graph.png"):
    """Generates a PDF report from text files in the output directory and embeds a graph."""
    print(f"[+] Generating PDF report: {report_filename}")
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    pdf.add_page()
    pdf.set_font("Arial", "B", 24)
    pdf.cell(0, 20, "WebSecAnalyzer Scan Report", ln=True, align="C")
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
    pdf.ln(20)

    if graph_image_path and os.path.exists(graph_image_path):
        try:
            pdf.set_font("Arial", "B", 16)
            pdf.cell(0, 10, "Scan Summary Graph", ln=True, align="L")
            img_width = pdf.w - 2 * pdf.l_margin
            pdf.image(graph_image_path, x=pdf.l_margin, w=img_width)
            pdf.ln(5)
        except Exception as e:
            print(colored(f"    Could not embed graph {graph_image_path} in PDF: {e}", "red"))
    else:
        print(colored(f"    Graph image '{graph_image_path}' not found or not specified. Skipping embedding in PDF.", "yellow"))

    if not os.path.exists(output_dir):
        print(colored(f"    Output directory '{output_dir}' not found. No text content for PDF.", "red"))
    else:
        file_list = sorted([f for f in os.listdir(output_dir) if f.endswith(".txt")])

        for txt_filename in file_list:
            pdf.add_page()
            pdf.set_font("Courier", "B", 14)
            section_title = txt_filename.replace(".txt", "").replace("_", " ").title()
            pdf.cell(0, 10, section_title, ln=True, align="L")
            pdf.ln(5)

            pdf.set_font("Courier", "", 9)
            file_path = os.path.join(output_dir, txt_filename)
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as file:
                    content = file.read()
                pdf.multi_cell(0, 4, content)
            except Exception as e:
                pdf.multi_cell(0, 4, f"Error reading file {txt_filename}: {e}")
                print(colored(f"    Error reading {file_path} for PDF: {e}", "red"))
            pdf.ln(5)

    try:
        pdf.output(report_filename, "F")
        print(colored(f"    PDF report generated successfully: {report_filename}", "green"))
    except Exception as e:
        print(colored(f"    Failed to save PDF report {report_filename}: {e}", "red"))


# --- Argument Parsing & Main Execution ---
def parse_arguments():
    parser = argparse.ArgumentParser(
        description=colored("WebSecAnalyzer - Web Application Security Scanner", "cyan", attrs=["bold"]),
        epilog="Example: python %(prog)s -d example.com -o report.pdf --auto-csrf"
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-d", "--domain", help="Target domain (e.g., example.com)", type=str)
    target_group.add_argument("-u", "--url", help="Target URL (e.g., https://example.com)", type=str)
    target_group.add_argument("-ip", "--ip_address", help="Target IP address (e.g., 192.168.1.1)", type=str)

    parser.add_argument("-ws", "--subdomain_wordlist", help="Path to subdomain wordlist", type=str, default=wordlist_sub_default)
    parser.add_argument("-wd", "--directory_wordlist", help="Path to directory wordlist", type=str, default=wordlist_dic_default)
    parser.add_argument("-wf", "--file_wordlist", help="Path to file wordlist", type=str, default=wordlist_file_default)
    parser.add_argument("-dpt", "--depth", help="Crawler max depth", type=int, default=2)
    parser.add_argument("-r", "--resolvers", help="File with DNS resolvers for external tools (Linux only)", type=str, default="wordlist/resolvers.txt")
    parser.add_argument("-o", "--output_file", help="Name of the PDF output file", type=str, default="WebSecAnalyzer_Report.pdf")
    parser.add_argument("--threads", type=int, default=20, help="Number of threads for concurrent requests (default: 20)")


    auth_group = parser.add_argument_group(title="Authentication Options")
    auth_group.add_argument("--login-url", help="Login page URL for authenticated scan", type=str)
    auth_group.add_argument("--username", help="Username for authentication", type=str)
    auth_group.add_argument("--password", help="Password for authentication", type=str)
    auth_group.add_argument("--username-field", help="Username input field name (default: username)", type=str, default="username")
    auth_group.add_argument("--password-field", help="Password input field name (default: password)", type=str, default="password")
    auth_group.add_argument("--login-success-keyword", help="A specific keyword in response text to confirm successful login", type=str)
    auth_group.add_argument("--login-debug", action="store_true", help="Enable detailed debug logging for the login process")
    auth_group.add_argument("--unauthenticated-only", action="store_true", help="Skip authentication attempt even if credentials are provided.")
    auth_group.add_argument("--export-session-cookies", help="File path to export session cookies after successful login (Netscape format)", type=str)
    auth_group.add_argument("--auth-header", help="Custom authorization header (e.g., \"Authorization: Bearer TOKEN_HERE\")", type=str)
    auth_group.add_argument("--auto-csrf", action="store_true", help="Attempt to automatically find and include CSRF tokens in login POST requests.")
    auth_group.add_argument("--auto-fields", action="store_true", help="Attempt to automatically detect username/password field names and other hidden fields from the login form.")

    return parser.parse_args()

def run_command(command_str, log_file_base=None):
    """
    Runs an external command.
    Note: shell=True can be a security risk if command components are from untrusted input.
    """
    print(colored(f"[CMD] Executing: {command_str}", "magenta"))
    try:
        process = subprocess.run(command_str, shell=True, check=True, capture_output=True, text=True, timeout=300)
        if log_file_base:
            append_to_file(f"raw/{log_file_base}_stdout.txt", process.stdout)
            if process.stderr:
                append_to_file(f"raw/{log_file_base}_stderr.txt", process.stderr)
        print(colored(f"    Command successful.", "blue"))
        if process.stdout.strip(): print(colored(f"    Output (first 100 chars): {process.stdout.strip()[:100]}...", "light_grey"))

    except subprocess.CalledProcessError as e:
        print(colored(f"    Error executing command: {command_str}\n    Return Code: {e.returncode}", "red"))
        if log_file_base:
            append_to_file(f"raw/{log_file_base}_error.txt", f"Error: {e}\nStdout: {e.stdout}\nStderr: {e.stderr}")
        if e.stdout: print(colored(f"    Stdout: {e.stdout.strip()}", "red"))
        if e.stderr: print(colored(f"    Stderr: {e.stderr.strip()}", "red"))
    except FileNotFoundError:
        tool_name = command_str.split()[0]
        print(colored(f"    Error: Command not found (ensure '{tool_name}' is installed and in PATH, or it's a valid shell command): {command_str}", "red"))
        if log_file_base: append_to_file(f"raw/{log_file_base}_error.txt", f"Command not found: {tool_name}")
    except subprocess.TimeoutExpired:
        print(colored(f"    Timeout executing command: {command_str}", "red"))
        if log_file_base: append_to_file(f"raw/{log_file_base}_error.txt", "Command timed out after 5 minutes.")


def is_alive(target_host_or_url):
    """
    Checks if a target is alive by making HTTP/HTTPS GET requests.
    Prioritizes HTTPS, then falls back to HTTP.
    Returns the working URL (with scheme) or None.
    """
    # If the user explicitly provided a scheme, try only that one first
    parsed_input = urlparse(target_host_or_url)
    schemes_to_try = []

    if parsed_input.scheme:
        schemes_to_try.append(parsed_input.scheme)
        # If the input explicitly has a scheme, also try the other common one as a fallback
        if parsed_input.scheme == "https":
            schemes_to_try.append("http")
        elif parsed_input.scheme == "http":
            schemes_to_try.append("https")
    else:
        # If no scheme is provided, try HTTPS first for better security defaults
        schemes_to_try.append("https")
        schemes_to_try.append("http")

    # Ensure uniqueness of schemes to avoid redundant attempts
    schemes_to_try = list(dict.fromkeys(schemes_to_try)) # Python 3.7+ preserves order

    for scheme in schemes_to_try:
        current_target_url = f"{scheme}://{parsed_input.netloc if parsed_input.netloc else parsed_input.path}"
        # Re-add path, query, fragment if they were present in the original input
        if parsed_input.path and not parsed_input.netloc: # Case where input was just 'domain.com/path'
             current_target_url = f"{scheme}://{parsed_input.path}"
        if parsed_input.query:
             current_target_url += "?" + parsed_input.query
        if parsed_input.fragment:
             current_target_url += "#" + parsed_input.fragment

        try:
            print(f"    Attempting to check liveness: {current_target_url}")
            response = requests.get(current_target_url, timeout=7, allow_redirects=True, verify=False)
            if response.status_code < 500: # Any 2xx, 3xx, 4xx implies host is up
                print(colored(f"    Target is alive at {response.url} (Status: {response.status_code})", "green"))
                return response.url # Return the final URL after redirects, which is the live one
        except ReqExc as e:
            print(f"    Liveness check failed for {current_target_url}: {e}")
            continue # Try next scheme

    return None # No scheme worked

def export_cookies_to_netscape_file(session_cookies, filepath):
    """Exports requests.cookies.RequestsCookieJar to a Netscape cookie file."""
    if not session_cookies:
        print(colored("    No session cookies to export.", "yellow"))
        return
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("# Netscape HTTP Cookie File\n")
            f.write("# http://curl.haxx.se/rfc/cookie_spec.html\n")
            f.write("# This is a generated file! Do not edit.\n\n")
            for cookie in session_cookies:
                domain_specified = "TRUE" if cookie.domain_specified else "FALSE"
                secure = "TRUE" if cookie.secure else "FALSE"
                expires = str(cookie.expires) if cookie.expires is not None else "0"
                f.write(f"{cookie.domain}\t{domain_specified}\t{cookie.path}\t{secure}\t{expires}\t{cookie.name}\t{cookie.value}\n")
        print(colored(f"    Session cookies exported to Netscape format: {filepath}", "green"))
    except Exception as e:
        print(colored(f"    Error exporting session cookies: {e}", "red"))


if __name__ == "__main__":
    main_start_time = datetime.now()

    ascii_banner = pyfiglet.figlet_format("WebSecAnalyzer", font="slant")
    print(colored(ascii_banner, "cyan", attrs=["bold"]))
    print(colored("Developed by: Abdullah Riaz, Ayaan Butt, M. Hamza Hussain", "green"))
    print("-" * 70)

    args = parse_arguments()

    target_input = args.domain or args.url or args.ip_address

    print(f"[+] Target specified: {target_input}")

    # --- CRITICAL FIX: Determine canonical working URL (with scheme) early ---
    # `is_alive` will now return the actual working URL (e.g., http://example.com)
    validated_target_url = is_alive(target_input)
    if not validated_target_url:
        print(colored(f"[!] Error: The target '{target_input}' is not reachable via HTTP or HTTPS. Exiting.", "red"))
        sys.exit(1)

    # Update primary_domain and primary_ip based on the *validated* URL
    primary_domain = extract_domain(validated_target_url)
    primary_ip = get_ip_from_domain(primary_domain) # Resolve IP from working domain

    print(colored(f"[+] Target '{target_input}' seems to be alive via {validated_target_url}.", "green"))


    validate_wordlist(args.subdomain_wordlist)
    validate_wordlist(args.directory_wordlist)
    validate_wordlist(args.file_wordlist)

    authenticated_session = None
    auth_method_used = "None"

    if args.auth_header and not args.unauthenticated_only:
        print(colored(f"[+] Attempting authentication using custom header: {args.auth_header.split(':')[0]}:******", "blue"))
        authenticated_session = requests.Session()
        # Add retry logic to the session
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]) # Add 429
        adapter = HTTPAdapter(max_retries=retries)
        authenticated_session.mount('http://', adapter)
        authenticated_session.mount('https://', adapter)

        authenticated_session.headers.update({'User-Agent': get_random_user_agent()})
        try:
            header_key, header_value = args.auth_header.split(":", 1)
            authenticated_session.headers[header_key.strip()] = header_value.strip()
            auth_method_used = "Header"
            print(colored("[+] Custom authentication header set in session.", "green"))

            auth_log_file = "raw/authenticated_session_log.txt"
            log_content = f"--- Authentication via Header at {datetime.now()} ---\n"
            log_content += f"Target Input: {target_input}\nHeader: {header_key.strip()}:******\n"
            log_content += f"Session Headers After Auth: {json.dumps(dict(authenticated_session.headers), indent=2)}\n\n"
            append_to_file(auth_log_file, log_content)

            if args.export_session_cookies:
                export_cookies_to_netscape_file(authenticated_session.cookies, args.export_session_cookies)
        except ValueError:
            print(colored(f"[!] Invalid format for --auth-header. Expected 'Header-Name: Header-Value'. Got: {args.auth_header}", "red"))
            authenticated_session = None

    elif args.username and args.password and not args.unauthenticated_only:
        # Use the validated_target_url as the default login_url if not specified
        login_url_to_use = args.login_url if args.login_url else validated_target_url
        # No need to normalize_url here, as validated_target_url already has correct scheme
        # if not (login_url_to_use.startswith("http")):
        #     login_url_to_use = normalize_url(login_url_to_use)

        authenticated_session = attempt_login(
            login_url_to_use,
            args.username,
            args.password,
            args.username_field,
            args.password_field,
            args.login_success_keyword,
            args.login_debug,
            args.auto_csrf,
            args.auto_fields # Pass auto_fields argument
        )
        if authenticated_session:
            print(colored("[+] Form-based authentication successful. Proceeding with authenticated session.", "green"))
            auth_method_used = "Login Form"
            if args.export_session_cookies:
                export_cookies_to_netscape_file(authenticated_session.cookies, args.export_session_cookies)
        else:
            print(colored("[-] Form-based authentication failed or credentials not fully processed. Proceeding with unauthenticated scan.", "yellow"))

    elif args.unauthenticated_only:
        print(colored("[+] --unauthenticated-only flag set. Skipping all authentication attempts.", "yellow"))
    else:
        print(colored("[+] No credentials or auth-header provided. Proceeding with unauthenticated scan.", "yellow"))

    if authenticated_session:
        print(colored(f"[*] Authenticated scan active (Method: {auth_method_used}). Subsequent requests will use the session.", "blue"))
    else:
        print(colored("[*] Unauthenticated scan active.", "blue"))

    # The primary_ip and primary_domain are already correctly set from validated_target_url above.
    print(f"[+] Effective Target URL for scanning: {validated_target_url}")
    if primary_domain: print(f"[+] Effective Target Domain: {primary_domain}")
    if primary_ip: print(f"[+] Effective Target IP: {primary_ip}")
    print("-" * 70)

    # All functions below should now receive `validated_target_url` for web scanning modules
    # and `primary_domain` / `primary_ip` for domain/IP-specific modules.

    if primary_domain: # WHOIS, DNS, SSL, CRT.sh still operate on domain
        whois_lookup(primary_domain)
        dns_lookup(primary_domain)
        # Only attempt SSL info if the validated URL actually uses HTTPS
        if validated_target_url.startswith("https://"):
            ssl_info_checker(primary_domain)
        else:
            print(colored("[!] Skipping SSL information check: Target URL is HTTP.", "yellow"))
        crtsh_lookup(primary_domain)
        # Pass the validated_target_url to subdomain_bruteforce so it can use the correct scheme
        subdomain_bruteforce(validated_target_url, args.subdomain_wordlist, authenticated_session, max_workers=args.threads)

        if sys.platform.startswith("linux"):
            print(colored("[i] Running external subdomain enumeration tools (Linux only)...", "cyan"))
            run_command(f"subfinder -d {primary_domain} -silent -o raw/subfinder_output.txt", "subfinder")
            run_command(f"assetfinder --subs-only {primary_domain} > raw/assetfinder_output.txt", "assetfinder")
            run_command(f"amass enum -passive -d {primary_domain} -o raw/amass_passive_output.txt", "amass_passive")

            combined_subs_file = "raw/all_discovered_subs_temp.txt"
            with open(combined_subs_file, "w", encoding="utf-8") as f_comb: pass
            for tool_out_file in ["raw/subfinder_output.txt", "raw/assetfinder_output.txt", "raw/amass_passive_output.txt", "raw/sub_brute_domains_200.txt"]:
                if os.path.exists(tool_out_file):
                    with open(tool_out_file, "r", encoding="utf-8") as infile, open(combined_subs_file, "a", encoding="utf-8") as outfile:
                        outfile.write(infile.read())

            run_command(f"cat {combined_subs_file} | sort -u > raw/all_discovered_subs_sorted.txt", "sort_subs")

            httpx_base_cmd = f"httpx -silent -status-code -threads {args.threads} -timeout 10"
            run_command(f"{httpx_base_cmd} -list raw/all_discovered_subs_sorted.txt -mc 200 -o graph/httpx_200_output.txt", "httpx_200")
            run_command(f"{httpx_base_cmd} -list raw/all_discovered_subs_sorted.txt -mc 403 -o graph/httpx_403_output.txt", "httpx_403")

            with open("raw/httpx_resolved_all.txt", "w", encoding="utf-8") as f_httpx_all: pass
            for httpx_out in ["graph/httpx_200_output.txt", "graph/httpx_403_output.txt"]:
                if os.path.exists(httpx_out):
                     with open(httpx_out, "r", encoding="utf-8") as infile, open("raw/httpx_resolved_all.txt", "a", encoding="utf-8") as outfile:
                        outfile.write(infile.read())
            run_command(f"cat raw/httpx_resolved_all.txt | sort -u > raw/httpx_resolved_all_sorted.txt", "httpx_combine_resolved")
        else:
            print(colored("[!] Skipping Linux-specific external subdomain tools (not on Linux).", "yellow"))

    # Pass max_workers argument to enumeration functions
    enumerate_paths_generic(validated_target_url, args.directory_wordlist, "directory", "SA", authenticated_session, max_workers=args.threads)
    enumerate_paths_generic(validated_target_url, args.file_wordlist, "file", "SB", authenticated_session, max_workers=args.threads)
    enumerate_combined_paths(validated_target_url, args.directory_wordlist, args.file_wordlist, authenticated_session, max_workers=args.threads)

    crawler(validated_target_url, args.depth, authenticated_session)
    filter_urls("raw/crawler_output.txt", "raw/filtered_urls.txt")

    consolidated_url_file = gather_discovered_urls()
    find_emails(consolidated_url_file, authenticated_session)
    if primary_domain:
      clean_and_sort_emails(domain_scope=primary_domain)
    else:
      clean_and_sort_emails()

    files_to_check_for_403 = ["raw/directory_brute_403.txt", "raw/file_brute_403.txt", "raw/sub_brute_domains_403.txt"]
    if sys.platform.startswith("linux"):
        files_to_check_for_403.append("graph/httpx_403_output.txt")

    all_403_urls = set()
    for f_403_path in files_to_check_for_403:
        if os.path.exists(f_403_path):
            try:
                with open(f_403_path, 'r', encoding='utf-8') as file_403_content:
                    for line in file_403_content:
                        stripped_line = line.strip()
                        if stripped_line:
                            all_403_urls.add(stripped_line)
            except Exception as e:
                print(colored(f"Error reading 403 URLs from {f_403_path}: {e}", "red"))

    if all_403_urls:
        open("graph/403_bypass_successful_count.txt", 'w').close()
        open("raw/403_bypass_successful.txt", 'w').close()
        print(f"[+] Found {len(all_403_urls)} unique URLs with potential 403 status. Attempting bypass...")
        for url_403 in all_403_urls:
            bypass_403(url_403, authenticated_session)

    if primary_ip:
        run_nmap_scan(primary_ip, "-sS -Pn -T4 -sV -O --top-ports 1000", "General_Scan", "7")
        run_nmap_scan(primary_ip, "-Pn -T4 -A -p- -vv", "Aggressive_Scan_All_Ports", "8")
        run_nmap_scan(primary_ip, "-Pn -T4 -sC -sV -O -vv --top-ports 5000", "Default_Scripts_Top_5k_Ports", "9")
        run_nmap_scan(primary_ip, '-Pn -T4 -sV --script="banner,http-title,http-headers,vuln" -p T:80,443,8000,8080,8443 --script-args http.max-cache-size=0', "Web_Vuln_Light_Scan", "10")
        run_nmap_scan(primary_ip, '-sV -vv --script "ftp-*" -p 21', "FTP_Vuln_Scan", "11")
    else:
        print(colored("[!] No primary IP identified for Nmap scans. Skipping Nmap modules.", "yellow"))

    graph_generated = generate_graph(graph_dir="graph", output_image_file="scan_summary_graph.png")
    generate_pdf_report(
        report_filename=args.output_file,
        output_dir="output",
        graph_image_path="scan_summary_graph.png" if graph_generated else None
    )

    final_timestamp = datetime.now()
    print("-" * 70)
    print(colored(f"[+] WebSecAnalyzer scan completed at: {final_timestamp}", "green", attrs=["bold"]))
    print(colored(f"    Total execution time: {final_timestamp - main_start_time}", "green"))
    print(colored(f"    PDF Report saved as: {args.output_file}", "green"))
    print("-" * 70)