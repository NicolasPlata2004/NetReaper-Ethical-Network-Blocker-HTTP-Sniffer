# 🔴 NetReaper — Ethical Network Blocker & HTTP Sniffer

> ARP Spoofing tool and HTTP credentials sniffer built for educational purposes in Computer Networks courses.  
> Automatically discovers and blocks all devices on a local network using ARP poisoning, and captures credentials sent over unencrypted HTTP.

---

## ⚠️ Disclaimer

This tool is intended **strictly for educational use** in controlled environments such as:
- Your own Wi-Fi hotspot
- A personal router with devices you own
- Virtual machines in an isolated network

**Using this tool on public, corporate, or university networks without explicit written authorization is illegal** under cybersecurity laws (Colombia: Ley 1273 de 2009, and equivalent legislation in other countries). The author is not responsible for any misuse.

---

## 📖 How It Works

### ARP Blocker
NetReaper exploits a fundamental weakness in the **ARP (Address Resolution Protocol)**: it has no authentication mechanism. Any device on the network can claim to be any IP address.

The attack works in two steps:

1. **ARP Sweep** — Sends broadcast ARP requests to discover all active devices on the `/24` subnet.
2. **ARP Poisoning** — Continuously sends fake ARP replies to each victim telling them:
   - *"I am the gateway"* → so their traffic goes nowhere
   - *"I am the victim"* → so the gateway stops routing for them

```
Normal flow:
  Victim ──────────────────► Gateway ──► Internet

After ARP poisoning:
  Victim ──► Attacker (us) ──► nowhere  (traffic dropped)
```

When stopped with `Ctrl+C`, the tool **restores all ARP tables** automatically so no device is left permanently disconnected.

### HTTP Sniffer
Listens passively on port 80 for HTTP POST requests containing login fields such as `username`, `password`, `email`, etc. Since HTTP transmits data in **plain text**, credentials are fully readable. This demonstrates exactly why HTTPS exists.

---

## ✨ Features

- ✅ **Fully automatic** — no manual configuration needed
- ✅ **New: Automated Discovery** — Performs a silent multi-threaded ping sweep to populate ARP tables, ensuring 100% device detection on Windows.
- ✅ Detects active network interface, IP, gateway, and subnet automatically
- ✅ Scans and blocks **all devices** on the network simultaneously
- ✅ Re-scans every 30 cycles to catch **newly connected devices**
- ✅ **Clean restoration** of ARP tables on exit (`Ctrl+C`)
- ✅ HTTP sniffer parses and displays **user/password cleanly**
- ✅ Works on Windows (and Linux with minor adjustments)

---

## 🛠️ Requirements

| Requirement | Download |
|---|---|
| Python 3.x | [python.org](https://python.org/downloads) |
| Npcap | [npcap.com](https://npcap.com) |
| Scapy | `pip install scapy` |

### Installation

**1. Install Python**  
During installation, check ✅ **"Add Python to PATH"**

**2. Install Npcap**  
During installation, check ✅ **"Install Npcap in WinPcap API-compatible Mode"**

**3. Install Scapy**  
Open CMD as Administrator and run:
```bash
pip install scapy
```

---

## 🚀 Usage

Always open **CMD as Administrator** (required for raw packet access).

### ARP Blocker
```bash
python arp_blocker_fixed.py
```

Expected output:
```
=======================================================
       ARP BLOCKER — Modo Automatico
=======================================================
[+] Interfaz : Wi-Fi
[+] Mi IP    : 192.168.1.108
[+] Gateway  : 192.168.1.1
[+] Rango    : 192.168.1.0/24

[+] MAC Gateway : e8:65:d4:4a:03:38

[*] Escaneando 192.168.1.0/24...
    [+] 192.168.1.105  |  ec:2e:98:63:af:83
    [+] 192.168.1.103  |  46:02:58:85:47:c2

[!] 2 dispositivo(s) a bloquear
[*] Ciclo 8 — 2 bloqueado(s)
```

Press **Ctrl+C** to stop and restore all devices automatically.

### HTTP Sniffer
```bash
python http_sniffer.py
```

Then open any HTTP (not HTTPS) login page from any device on the same network and submit credentials. Expected output:
```
============================================================
  [!] CREDENCIALES CAPTURADAS
============================================================
  Sitio     : zero.webappsecurity.com
  Origen    : 192.168.1.108  ->  54.82.22.214
  Usuario   : admin
  Password  : 1234
============================================================
```

Test sites (HTTP only, made for security practice):
- http://testphp.vulnweb.com/login.php
- http://zero.webappsecurity.com/login.html

---

## 🛡️ Defenses (Blue Team)

| Attack | Defense |
|---|---|
| ARP Spoofing | Dynamic ARP Inspection (DAI) on managed switches |
| ARP Spoofing | Static ARP entries for critical hosts |
| HTTP sniffing | Enforce HTTPS / HSTS on all web services |
| Network recon | 802.1X port-based authentication |

---

## 📁 Project Structure

```
NetReaper/
├── arp_blocker_fixed.py   # Automatic ARP blocker — no config needed
├── http_sniffer.py       # HTTP credentials sniffer
└── README.md
```

---

## 📚 Educational Context

Built as a practical project for a **Computer Networks** university course, covering:
- ARP protocol internals and Layer 2 attack vectors
- Ethical hacking methodology
- Network defense strategies
- Why HTTPS and authenticated protocols exist

---

## 📄 License

For educational use only. Do not use on networks you do not own or have explicit permission to test.

---
---

# 🔴 NetReaper — Bloqueador de Red Ético & Sniffer HTTP

> Herramienta de ARP Spoofing y captura de credenciales HTTP construida con fines educativos para cursos de Redes de Computadores.  
> Descubre y bloquea automáticamente todos los dispositivos en una red local usando envenenamiento ARP, y captura credenciales enviadas por HTTP sin cifrar.

---

## ⚠️ Aviso Legal

Esta herramienta está destinada **estrictamente para uso educativo** en entornos controlados como:
- Tu propio hotspot de celular
- Un router personal con dispositivos de tu propiedad
- Máquinas virtuales en una red aislada

**Usar esta herramienta en redes públicas, corporativas o universitarias sin autorización escrita explícita es ilegal** bajo la **Ley 1273 de 2009** en Colombia (y legislación equivalente en otros países). El autor no se hace responsable por mal uso.

---

## 📖 Cómo Funciona

### ARP Blocker
NetReaper explota una debilidad fundamental del **Protocolo ARP (Address Resolution Protocol)**: no tiene mecanismo de autenticación. Cualquier dispositivo en la red puede afirmar ser cualquier dirección IP.

El ataque funciona en dos pasos:

1. **ARP Sweep** — Envía solicitudes ARP broadcast para descubrir todos los dispositivos activos en la subred `/24`.
2. **ARP Poisoning** — Envía continuamente respuestas ARP falsas a cada víctima diciéndoles:
   - *"Yo soy el gateway"* → el tráfico de la víctima no llega a ningún lado
   - *"Yo soy la víctima"* → el gateway deja de enrutar para ella

```
Flujo normal:
  Víctima ─────────────────► Gateway ──► Internet

Después del envenenamiento ARP:
  Víctima ──► Atacante (nosotros) ──► nowhere (tráfico descartado)
```

Al detener con `Ctrl+C`, la herramienta **restaura todas las tablas ARP** automáticamente para que ningún dispositivo quede permanentemente desconectado.

### HTTP Sniffer
Escucha pasivamente en el puerto 80 peticiones HTTP POST que contengan campos de login como `username`, `password`, `email`, etc. Como HTTP transmite los datos en **texto plano**, las credenciales son completamente legibles. Esto demuestra exactamente por qué existe HTTPS.

---

## ✨ Características

- ✅ **Totalmente automático** — sin configuración manual
- ✅ **Nuevo: Descubrimiento Automatizado** — Realiza un barrido de pings (ping sweep) silencioso y multihilo para despertar a la red antes del bloqueo.
- ✅ Detecta interfaz, IP, gateway y subred automáticamente
- ✅ Escanea y bloquea **todos los dispositivos** de la red simultáneamente
- ✅ Re-escanea cada 30 ciclos para detectar **nuevos dispositivos conectados**
- ✅ **Restauración limpia** de tablas ARP al salir (`Ctrl+C`)
- ✅ El sniffer HTTP parsea y muestra **usuario/contraseña de forma limpia**
- ✅ Funciona en Windows (y Linux con ajustes menores)

---

## 🛠️ Requisitos

| Requisito | Descarga |
|---|---|
| Python 3.x | [python.org](https://python.org/downloads) |
| Npcap | [npcap.com](https://npcap.com) |
| Scapy | `pip install scapy` |

### Instalación

**1. Instalar Python**  
Durante la instalación, marcar ✅ **"Add Python to PATH"**

**2. Instalar Npcap**  
Durante la instalación, marcar ✅ **"Install Npcap in WinPcap API-compatible Mode"**

**3. Instalar Scapy**  
Abrir CMD como Administrador y ejecutar:
```bash
pip install scapy
```

---

## 🚀 Uso

Siempre abrir **CMD como Administrador** (requerido para acceso a paquetes raw).

### ARP Blocker
```bash
python arp_blocker_fixed.py
```

Presiona **Ctrl+C** para detener y restaurar todos los dispositivos automáticamente.

### HTTP Sniffer
```bash
python http_sniffer.py
```

Luego abre cualquier página de login HTTP (no HTTPS) desde cualquier dispositivo en la misma red e intenta iniciar sesión.

Sitios de prueba (HTTP puro, hechos para práctica de seguridad):
- http://testphp.vulnweb.com/login.php
- http://zero.webappsecurity.com/login.html

---

## 🛡️ Defenses (Blue Team)

| Ataque | Defensa |
|---|---|
| ARP Spoofing | Dynamic ARP Inspection (DAI) en switches gestionados |
| ARP Spoofing | Entradas ARP estáticas para hosts críticos |
| Sniffing HTTP | Forzar HTTPS / HSTS en todos los servicios web |
| Reconocimiento de red | Autenticación de puerto 802.1X |

---

## 📁 Estructura del Proyecto

```
NetReaper/
├── arp_blocker_fixed.py   # Bloqueador ARP automático — sin configuración
├── http_sniffer.py       # Sniffer de credenciales HTTP
└── README.md
```

---

## 📚 Contexto Educativo

Construido como proyecto práctico para una materia de **Redes de Computadores**, cubriendo:
- Funcionamiento interno del protocolo ARP y vectores de ataque en Capa 2
- Metodología de hacking ético
- Estrategias de defensa de redes
- Por qué existen HTTPS y los protocolos autenticados

---

## 📄 Licencia

Solo para uso educativo. No usar en redes que no sean de tu propiedad o para las cuales no tengas permiso explícito de prueba.
