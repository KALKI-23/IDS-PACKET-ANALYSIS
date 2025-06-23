import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
from scapy.all import sniff, IP, TCP
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

packet_count = {}
THRESHOLD = 100
running = False

def detect_syn_flood(pkt):
    if IP in pkt and TCP in pkt:
        if pkt[TCP].flags == 'S':
            src_ip = pkt[IP].src
            packet_count[src_ip] = packet_count.get(src_ip, 0) + 1
            log = f"[LOG] SYN from {src_ip}, count: {packet_count[src_ip]}\n"
            log_text.insert(tk.END, log)
            log_text.see(tk.END)
            with open("ids_log.txt", "a") as logfile:
                logfile.write(log)

            if packet_count[src_ip] > THRESHOLD:
                alert = f"[ALERT] Possible SYN Flood from {src_ip}!\n"
                log_text.insert(tk.END, alert)
                with open("ids_log.txt", "a") as logfile:
                    logfile.write(alert)

def start_sniffing():
    global running
    running = True
    sniff(filter="tcp", prn=detect_syn_flood, store=0, stop_filter=lambda x: not running)

def start_thread():
    sniff_thread = Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

def stop_sniffing():
    global running
    running = False
    log_text.insert(tk.END, "[INFO] Stopped sniffing.\n")

def update_chart():
    ax.clear()
    ax.set_title("SYN Packets Per IP")
    ax.set_xlabel("IP Address")
    ax.set_ylabel("Packet Count")

    ip_list = list(packet_count.keys())
    count_list = list(packet_count.values())
    ax.bar(ip_list, count_list, color='red')
    canvas.draw()
    root.after(3000, update_chart)

# GUI Setup
root = tk.Tk()
root.title("Simple IDS - SYN Flood Detector")

tk.Label(root, text="Intrusion Detection System").pack()

log_text = scrolledtext.ScrolledText(root, height=15, width=80)
log_text.pack(pady=10)

btn_frame = tk.Frame(root)
btn_frame.pack()

start_btn = tk.Button(btn_frame, text="Start Sniffing", command=start_thread)
start_btn.pack(side=tk.LEFT, padx=10)

stop_btn = tk.Button(btn_frame, text="Stop Sniffing", command=stop_sniffing)
stop_btn.pack(side=tk.LEFT, padx=10)

exit_btn = tk.Button(btn_frame, text="Exit", command=root.destroy)
exit_btn.pack(side=tk.LEFT, padx=10)

# Chart setup
fig, ax = plt.subplots(figsize=(5, 3))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack()
update_chart()

root.mainloop()
