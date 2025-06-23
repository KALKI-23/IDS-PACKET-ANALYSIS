# 🔐 Intrusion Detection System using Packet Analysis

This project is a lightweight **Intrusion Detection System (IDS)** built using **Python** and **Scapy**, capable of detecting **SYN flood attacks** in real time.

It includes a **Tkinter-based GUI**, **log file generation**, and a **live-updating bar chart** to visualize incoming SYN packets per IP address.

---

## 🎯 Features

- ✅ Real-time TCP packet sniffing
- ✅ SYN flood attack detection
- ✅ Tkinter GUI with Start, Stop, and Exit buttons
- ✅ Live bar chart (matplotlib)
- ✅ Logs all packet activity to `ids_log.txt`

---

## 🛠️ Technologies Used

- **Python 3.11+**
- **Scapy** for packet capture
- **Matplotlib** for live charts
- **Tkinter** for GUI
- **Npcap** for packet access on Windows
- **hping3** (Kali) for simulating attacks

---

## 📦 Project Structure

ids-packet-analysis/
├── ids_gui_with_log_and_chart.py # Main IDS script
├── ids_log.txt # Automatically generated logs
├── IDS_Project_Step_by_Step_Guide.txt # Setup guide
├── README.md # This file
└── screenshots/ # (Optional screenshots of GUI/results)

yaml
Copy code

---

## 🚀 How to Run

### 📍 On Windows Host

1. Install dependencies:

```bash
pip install scapy matplotlib
Install Npcap (check "WinPcap Compatibility Mode")

Run the Python script as Administrator:

bash
Copy code
python ids_gui_with_log_and_chart.py
GUI will open with live logging and chart display.

💥 On Kali VM (Attacker Machine)
Install hping3:

bash
Copy code
sudo apt update
sudo apt install hping3
Simulate a SYN flood:

bash
Copy code
sudo hping3 -S -p 80 --flood <host_ip>
Replace <host_ip> with the IP address of your Windows machine.

📈 Sample Output
csharp
Copy code
[LOG] SYN from 192.168.0.21, count: 56
[LOG] SYN from 192.168.0.21, count: 101
[ALERT] Possible SYN Flood from 192.168.0.21!
The GUI will update in real-time and display packet statistics.

🚧 Known Issues
Npcap must be correctly installed for packet sniffing to work on Windows.

The firewall may need to be configured to allow sniffed packets.

Both host and VM must be on the same subnet using Bridged Network mode.

📚 Future Enhancements
Interface selection dropdown

Log export to CSV/JSON

Multiple attack type detection (port scan, ARP spoof, etc.)

Email/SMS alerts

GUI alert popups

🙋 Author
Kalki Krish
Final Year B.E. Cybersecurity – AVIT
📧 kalkikrish@example.com

📝 License
This project is open-source and available under the MIT License.

🙏 Acknowledgements
Scapy Docs – https://scapy.readthedocs.io/

Npcap by Nmap – https://nmap.org/npcap/

Kali Linux – https://www.kali.org/

yaml
Copy code
