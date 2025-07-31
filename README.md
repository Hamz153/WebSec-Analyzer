# WebSecAnalyzer
# WebSecAnalyzer

### A Cross-Platform Web Application Security Scanner for Automated Reconnaissance

WebSecAnalyzer is a powerful and flexible web application security scanning tool designed to automate the reconnaissance and initial vulnerability assessment process. Developed to address the challenges of using fragmented security tools, WebSecAnalyzer provides a single, cohesive solution that integrates custom Python scripts with powerful, industry-standard Linux utilities. [cite\_start]Its modular design allows for a streamlined workflow, enabling security professionals to efficiently identify potential weaknesses across various web applications[cite: 36, 52, 218].

### Key Features

  * [cite\_start]**Comprehensive Reconnaissance:** Automatically performs essential information gathering tasks to build a complete profile of the target[cite: 349, 760].

      * [cite\_start]WHOIS Lookups [cite: 376]
      * [cite\_start]DNS Resolution and Enumeration [cite: 374, 138]
      * [cite\_start]SSL Certificate Analysis [cite: 378]
      * [cite\_start]Certificate Transparency (via `crt.sh` integration) [cite: 379]

  * [cite\_start]**Advanced Enumeration & Discovery:** Utilizes powerful brute-forcing and crawling techniques to expand the attack surface[cite: 349, 765].

      * [cite\_start]**Subdomain Brute-forcing:** Discovers hidden or unknown subdomains using a custom wordlist[cite: 381].
      * [cite\_start]**Directory & File Brute-forcing:** Identifies accessible directories, files, and paths to reveal sensitive resources[cite: 382, 383, 385].
      * [cite\_start]**Website Crawling:** Recursively crawls a target to map its infrastructure and collect all internal URLs[cite: 386].
      * [cite\_start]**Email Extraction:** Scrapes email addresses from discovered web pages for further analysis or OSINT[cite: 388].

  * **Robust Vulnerability Assessment:** Integrates scanning and bypass capabilities for deeper analysis.

      * [cite\_start]**403 Bypass:** Attempts to circumvent `403 Forbidden` errors using various custom HTTP headers to access restricted content[cite: 389].
      * [cite\_start]**Nmap Scanning:** Leverages the Nmap network scanner for comprehensive port scanning, service version detection, OS fingerprinting, and vulnerability checks[cite: 390].
      * [cite\_start]**Linux Tool Integration:** On Linux systems, WebSecAnalyzer automatically integrates tools like `Subfinder` [cite: 325][cite\_start], `Httpx` [cite: 138][cite\_start], `Amass` [cite: 138][cite\_start], and `Nuclei` [cite: 330] [cite\_start]for faster, more accurate, and in-depth scanning[cite: 56, 261].

  * [cite\_start]**Automated Reporting:** Generates a professional, easy-to-read PDF report that aggregates all findings from the scan[cite: 391, 746].

      * [cite\_start]Includes a graphical summary of HTTP response codes to visualize results[cite: 188].
      * [cite\_start]All raw data is saved to dedicated files for deeper analysis or integration with other tools[cite: 354].

### Installation & Prerequisites

WebSecAnalyzer is built on Python 3.10+ and is designed for use on both Windows and Linux environments.

#### 1\. Python Libraries

First, install the required Python libraries using `pip`:

```bash
pip install -r requirements.txt
```

The `requirements.txt` file contains the following dependencies:

  * `requests`
  * `beautifulsoup4`
  * `python-nmap`
  * `dnspython`
  * `python-whois`
  * `fpdf`
  * `matplotlib`
  * `pyfiglet`
  * `termcolor`
  * `urllib3`

#### 2\. External Linux Tools

For the most accurate and comprehensive results on a Linux system (like Kali Linux), you must install several external command-line tools. WebSecAnalyzer will automatically detect and use these tools if they are available in your system's `PATH`.

```bash
sudo apt-get update
sudo apt-get install -y nmap
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/tomnomnom/gf@latest
go install github.com/blechschmidt/massdns/cmd/massdns@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
```

### Usage

[cite\_start]WebSecAnalyzer operates via a Command-Line Interface (CLI)[cite: 243]. You can specify a target using a domain, URL, or IP address.

#### Basic Scan

To run a full scan and generate a PDF report:

```bash
python3 websec_auth_updated6_gemni.py -d example.com -o WebSecAnalyzer_Report.pdf
```

#### Scan with Custom Wordlists

You can provide your own wordlists for subdomain, directory, and file brute-forcing:

```bash
python3 websec_auth_updated6_gemni.py -u https://example.com --subdomain-wordlist my_subs.txt --directory-wordlist my_dirs.txt --file-wordlist my_files.txt -o custom_report.pdf
```

#### Authenticated Scan

WebSecAnalyzer supports scans behind login pages. [cite\_start]It can auto-detect form fields and CSRF tokens[cite: 599, 606].

```bash
python3 websec_auth_updated6_gemni.py -u https://example.com --login-url https://example.com/login --username myuser --password mypass -o auth_report.pdf --auto-csrf --auto-fields
```

### Reporting

[cite\_start]The tool generates a detailed PDF report (`WebSecAnalyzer_Report.pdf` by default) containing a summary of all findings[cite: 391]. It also saves raw scan data in the `raw/` and `output/` directories for further analysis. [cite\_start]A visual graph is also generated and embedded in the report[cite: 188, 810].

### License

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**.

The GPLv3 license ensures that:

  * You are free to use and modify this software.
  * If you distribute a modified version or a tool based on this project, you must also make the source code available under the same license.
  * This protects the open-source nature of the project and ensures that all improvements and derivative works remain freely accessible to the community.

### Acknowledgements

This project was developed by:

  * M Hamza Hussain (F2021408051)
  * Abdullah Riaz (F2021408038)
  * Ayaan Butt (F2021408014)

Special thanks to our advisor, Dr. Amjad Hussain Zahid, for his invaluable guidance and mentorship.
