## 📦 Files

This release includes:
- `SAVIOR.exe` - Main executable
- `2captcha.py` - CAPTCHA solver script
- `call_2captcha.py` - CAPTCHA wrapper script

## ⚠️ Prerequisites

**You MUST install and configure the following before using this tool:**
Operating System：Windows

### 1. Python 3.7+
Download and install from: https://www.python.org/downloads/

### 2. Python Dependencies
```bash
pip install twocaptcha-python
```

### 3. Claude CLI (Required)
Install Claude CLI and ensure it's in your system PATH.
Get it from: https://claude.ai/

### 4. Playwright MCP (Required)
The tool uses Playwright MCP for browser automation.
Follow Playwright installation instructions.

### 5. 2Captcha API Key (Optional but Recommended)
Get an API key from: https://2captcha.com

Set environment variable:
```powershell
$env:TWOCAPTCHA_API_KEY = "your_api_key_here"
```

## 🚀 Usage
### Quick Start
```powershell
# Create a URL list file
echo "zoom.com" > urls.txt
echo "pinterest.com" >> urls.txt

# Run the tool
.\SAVIOR.exe --url-file urls.txt
```

### Available Commands

```powershell
# OAuth Test Runner
.\SAVIOR.exe --url-file urls.txt
.\SAVIOR.exe --urls zoom.com adobe.com

## 📂 Output

Tests create the following folders:
```
OAuth_support/          # OAuth detection results
T1_step1_results/       # Test results
T1_step1_Screenshots/   # Screenshots
... (other test folders)
```

## 🔒 Legal & Ethics

**Important**: This tool is a demo version for the basic authorized security testing only.
- Only test websites you have permission to test
- Respect terms of service
- Use responsibly and ethically