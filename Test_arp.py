from scapy.all import ARP, Ether, srp, IFACES
import socket

# Detectar interfaz
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
mi_ip = s.getsockname()[0]
s.close()

interfaz = None
for k, v in IFACES.items():
    try:
        if hasattr(v, 'ip') and v.ip == mi_ip:
            interfaz = k
            break
    except:
        continue

if not interfaz:
    print("[!] No se encontró interfaz")
    exit(1)

print(f"[*] Usando interfaz: {interfaz}")
print(f"[*] Mi IP: {mi_ip}")

# Test 1: Escanear solo el gateway
print("\n[TEST 1] Escaneando solo el gateway (192.168.1.1)...")
paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.1")
resp, _ = srp(paquete, iface=interfaz, timeout=5, verbose=True)
print(f"Respuestas: {len(resp)}")
for s, r in resp:
    print(f"  -> {r[ARP].psrc} : {r[ARP].hwsrc}")

# Test 2: Escanear las IPs específicas que arp -a mostró
print("\n[TEST 2] Escaneando 192.168.1.111 y 192.168.1.134...")
for ip in ["192.168.1.111", "192.168.1.134"]:
    paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    resp, _ = srp(paquete, iface=interfaz, timeout=5, verbose=True)
    if resp:
        print(f"  ✓ {ip} respondió: {resp[0][1].hwsrc}")
    else:
        print(f"  ✗ {ip} NO respondió")

print("\n[*] Si ningún test respondió, Kaspersky está bloqueando ARP.")