# 🔥 WafHunter

<div align="center">

```
$$\      $$\  $$$$$$\  $$$$$$$$\ $$\   $$\                      $$\                         
$$ | $\  $$ |$$  __$$\ $$  _____|$$ |  $$ |                     $$ |                        
$$ |$$$\ $$ |$$ /  $$ |$$ |      $$ |  $$ |$$\   $$\ $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\  
$$ $$ $$\$$ |$$$$$$$$ |$$$$$\    $$$$$$$$ |$$ |  $$ |$$  __$$\\_$$  _|  $$  __$$\ $$  __$$\ 
$$$$  _$$$$ |$$  __$$ |$$  __|   $$  __$$ |$$ |  $$ |$$ |  $$ | $$ |    $$$$$$$$ |$$ |  \__|
$$$  / \$$$ |$$ |  $$ |$$ |      $$ |  $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ $$   ____|$$ |      
$$  /   \$$ |$$ |  $$ |$$ |      $$ |  $$ |\$$$$$$  |$$ |  $$ | \$$$$  |\$$$$$$$\ $$ |      
\__/     \__|\__|  \__|\__|      \__|  \__| \______/ \__|  \__|  \____/  \_______|\__|      
```

**A cross-platform WAF and firewall detection tool**

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#)

</div>

---

## 📋 Overview

**WafHunter** is a Web Application Firewall (WAF) detection tool for security researchers and penetration testers. It combines active HTTP probing with passive SSL/TLS analysis to identify WAF vendors protecting web applications.

## ✨ Features

- 🎯 **Multi-Vendor Detection** - Cloudflare, AWS WAF, Fortinet, Sophos
- 🔍 **Dual Detection** - Active HTTP probes + passive certificate analysis
- 📊 **Scoring System** - Weighted algorithm for accurate detection
- 🌐 **Cross-Platform** - Windows, Linux, macOS
- ⚡ **Fast & Efficient** - Configurable timeout and smart probing
- 🔒 **SSL/TLS Analysis** - Certificate CommonName and SAN extraction

## 🚀 Installation

### Prerequisites
- Python 3.7+
- pip

### Install

1. **Clone the repository**
   ```bash
   git clone https://github.com/TheWildEye/WAFHunter.git
   cd WAFHunter
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

### Running the Tool

**Windows (CMD/PowerShell):**
```cmd
python firewall.py
```

**Linux/macOS:**
```bash
python3 firewall.py
```

### Input

Enter a target URL when prompted:
```
Enter target URL: example.com
```

Supported formats:
- `example.com`
- `https://example.com`
- `http://example.com/path`

## 🧠 How It Works

### Active Probing
Sends crafted HTTP requests to trigger WAF responses:
- Normal GET request
- XSS payload: `<script>alert(1)</script>`
- SQL injection: `' OR '1'='1`
- POST and HEAD requests

### Passive Analysis
- DNS resolution
- SSL/TLS certificate inspection (CN, SAN)
- Header and cookie examination

### Scoring Algorithm
Detection points:
- **Header match**: +6
- **SSL/TLS match**: +6  
- **Body match**: +4
- **Suspicious status codes** (403, 406, 429, 501, 503): +3
- **Cookie match**: +2

Threshold: 8 points for positive detection

## 🛡️ Supported WAFs

| Vendor | Detection Methods |
|--------|-------------------|
| **Cloudflare** | cf-ray header, cloudflare server, CF cookies, SSL CN/SAN |
| **AWS WAF / CloudFront** | x-amz headers, CloudFront via, AWS cookies, SSL CN/SAN |
| **Fortinet** | Forti headers, Fortinet/FortiWeb strings, SSL CN/SAN |
| **Sophos** | Sophos headers, body strings, SSL CN/SAN |

## 🔧 Configuration

Edit constants in `firewall.py`:

```python
TIMEOUT = 7      # Request timeout in seconds
THRESHOLD = 8    # Minimum score for detection
```

Add custom WAF signatures to the `VENDORS` dictionary.

## ⚠️ Legal Disclaimer

**For authorized security testing only.** Only scan systems you own or have explicit permission to test. The authors are not responsible for misuse.

---

<div align="center">

**Made for the security community**

⭐ Star this repo if you find it useful!

</div>
