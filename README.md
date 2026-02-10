<img width="1536" height="1024" alt="hashcat-gui-logo" src="https://github.com/user-attachments/assets/5ad50fee-6e95-4af1-afdf-4fe611dba66c" />

# A web browser-based GUI for using Hashcat on Ubuntu! Now with functional hash extraction tools.

# For hashcat-gui installation first run:
```
sudo apt update && sudo apt install hashcat john hcxtools

sudo python3 -m pip install flask werkzeug --break-system-packages
```
# For NVIDIA GPU drivers, run:
```
sudo apt update

sudo ubuntu-drivers autoinstall -y 

sudo reboot
```
# Ensure that you see the GPU listed as Device #1 or Device #2
```
hashcat -I
```
# Launch hashcat-gui from the hashcat-gui/ folder and navigate to localhost:5000 in the web browser

```
python3 hashcat-gui.py
```

To use hash extractor tools, double check that office2john.py is saved in your /usr/share/john/ directory.

<img width="1146" height="1040" alt="image" src="https://github.com/user-attachments/assets/46c4012d-9710-4eda-aeeb-403d87e8262b" />


<h2 align="center">⚠️ Disclaimer</h2>

<p style="color:#ff4d4d; font-weight:500;">

This project is provided strictly for <strong>educational, research, and authorized security testing purposes</strong>.

By using this software, you agree to operate it only on systems, devices, and accounts that you <strong>own</strong> or have <strong>explicit written permission</strong> to test. Unauthorized password cracking, access attempts, or security testing may violate local, state, federal, or international laws.

The author and contributors:

• Do <strong>not</strong> condone illegal or unethical activity.

• Are <strong>not liable</strong> for misuse, damages, or legal consequences.

• Provide this software <strong>as-is</strong>, without warranty or guarantee.

• Do <strong>not</strong> claim ownership of Hashcat, John the Ripper, Office2John, or hcxtools; all rights remain with their respective owners.

You assume <strong>full responsibility</strong> for how this tool is used.

If you are unsure whether your intended use is authorized or legal, <strong>do not proceed</strong>.

</p>


<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License">
</p>
