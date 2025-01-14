from scapy.all import sniff
import json

# Engelleme kontrol fonksiyonu
def check_rules(packet):
    with open("rules.json", "r") as f:
        rules = json.load(f)

    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_port = packet["TCP"].dport if packet.haslayer("TCP") else None
        
        # IP kontrolü
        if src_ip in rules["blocked_ips"]:
            log_packet(packet, "Engellendi - IP")
            return False
        
        # Port kontrolü
        if dst_port and str(dst_port) in rules["blocked_ports"]:
            log_packet(packet, "Engellendi - PORT")
            return False
        
    log_packet(packet, "İzin Verildi")
    return True

# Paket günlüğü kaydetme
def log_packet(packet, status):
    with open("firewall.log", "a") as f:
        f.write(f"{status}: {packet.summary()}\n")
    print(f"{status}: {packet.summary()}")

# Trafik dinleme
def start_firewall():
    sniff(prn=check_rules, filter="ip", store=0)

