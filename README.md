🛡️ HAMZXA1 Security Tool

A lightweight Windows security utility built to detect, clean, and remove common USB and System32-based malware.
Designed with a modern interface using Tkinter and focused on aggressive but safe threat removal.

📌 Features
🔍 System Scanner

Detects malicious folders like wsvcz.

Identifies suspicious u#####.dll files in System32.

Allows:

Immediate aggressive deletion

Schedule deletion on next reboot

💾 USB Cleaner

Removes shortcut-virus infections.

Restores hidden files from USB drives.

Removes malicious folders (e.g., sysvolume).

Fixes attributes (read-only, system, hidden).

🧰 Core Capabilities

Ownership-taking to bypass protected files.

Kills processes locking a file.

Cleans attributes before performing deletion.

Logs all actions to HAMZXA1_log.txt.

🎨 Modern UI

Dark theme

Clean card-based layout

Real-time action logs

Update checker integrated with GitHub

🚀 How to Run

Install Python 3.10+

Install required modules:

pip install psutil


Run the tool:

python HAMZXA1.py

📦 Build EXE (Optional)

Using PyInstaller:

pyinstaller --noconfirm --onefile --windowed --icon=icon.ico HAMZXA1.py


If your exe uses resources (icons, images):

pyinstaller --noconfirm --windowed --add-data "icon.ico;." HAMZXA1.py

📄 Log File

All actions are logged in:

HAMZXA1_log.txt


Useful for debugging or checking what operations were done.

📬 Updates

The tool checks for updates automatically through GitHub.

⚠️ Disclaimer

This tool is intended for educational and personal use only.
Use responsibly and at your own risk.
