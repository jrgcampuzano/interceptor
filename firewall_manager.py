# -*- coding: utf-8 -*-
"""
INTERCEPTOR — Módulo de firewall (nftables / OpenWrt fw4)

Opera desde Raspberry Pi hacia router OpenWrt 24.10.3 vía SSH.

Operaciones:
    - block_ip(ip, ttl_hours)     → 4 reglas (IN/OUT × tcp/udp) + conntrack -D
    - unblock_ip(ip)              → Elimina reglas por handle
    - is_blocked(ip)              → Verifica existencia de reglas
    - get_blocked_list()          → Lista IPs bloqueadas con metadata
    - cleanup_expired()           → Desbloquea IPs con TTL expirado

Patrón nftables:  !fw4: GOSIP_<IP>_IN  /  !fw4: GOSIP_<IP>_OUT
"""

import subprocess
import json
import os
import time
import threading
import re
from datetime import datetime

from config import (
    ROUTER_IP, ROUTER_USER, CLEANUP_INTERVAL, BASE_DIR
)

# ==============================================================================
# CONFIGURACIÓN SSH
# ==============================================================================
SSH_CMD_PREFIX = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no {ROUTER_USER}@{ROUTER_IP}"

NFT_TABLE = 'inet fw4'
NFT_CHAIN = 'forward'

BLOCK_REGISTRY_FILE = os.path.join(BASE_DIR, 'blocked_ips.json')

# ==============================================================================
# EJECUCIÓN REMOTA SSH
# ==============================================================================

def _ssh_exec(command):
    """Ejecuta un comando en el router vía SSH. Retorna (success, stdout, stderr)."""
    full_cmd = f'{SSH_CMD_PREFIX} "{command}"'
    try:
        result = subprocess.run(
            full_cmd, shell=True, capture_output=True, text=True, timeout=15
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, '', 'SSH timeout'
    except Exception as e:
        return False, '', str(e)

# ==============================================================================
# REGISTRO LOCAL DE IPs BLOQUEADAS
# ==============================================================================

_registry_lock = threading.Lock()


def _load_registry():
    """Carga el registro de IPs bloqueadas desde disco."""
    if not os.path.exists(BLOCK_REGISTRY_FILE):
        return {}
    try:
        with open(BLOCK_REGISTRY_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def _save_registry(registry):
    """Guarda el registro de IPs bloqueadas a disco."""
    try:
        with open(BLOCK_REGISTRY_FILE, 'w') as f:
            json.dump(registry, f, indent=2)
    except IOError as e:
        print(f"❌ [FW] Error guardando registro: {e}")


def _register_block(ip, ttl_hours):
    """Registra una IP bloqueada con su timestamp y TTL."""
    with _registry_lock:
        registry = _load_registry()
        registry[ip] = {
            'blocked_at': datetime.now().isoformat(),
            'blocked_ts': time.time(),
            'ttl_hours': ttl_hours
        }
        _save_registry(registry)


def _unregister_block(ip):
    """Elimina una IP del registro local."""
    with _registry_lock:
        registry = _load_registry()
        if ip in registry:
            del registry[ip]
            _save_registry(registry)
            return True
        return False

# ==============================================================================
# OPERACIONES DE FIREWALL (nftables)
# ==============================================================================

def is_blocked(ip):
    """Verifica si una IP ya tiene reglas de bloqueo en el router."""
    tag = f"GOSIP_{ip}_IN"
    success, stdout, _ = _ssh_exec(f"nft list chain {NFT_TABLE} {NFT_CHAIN} | grep '{tag}'")
    return success and tag in stdout


def block_ip(ip, ttl_hours=24):
    """
    Bloquea una IP en el firewall del router.

    Crea 4 reglas: tcp/udp × entrada/salida.
    Luego mata conexiones activas con conntrack.

    Args:
        ip: Dirección IP a bloquear
        ttl_hours: Horas hasta desbloqueo automático. 0 = permanente.

    Returns:
        dict con 'success', 'message', 'rules_created'
    """
    if is_blocked(ip):
        return {
            'success': False,
            'message': f'IP {ip} ya está bloqueada',
            'rules_created': 0
        }

    tag_in = f"GOSIP_{ip}_IN"
    tag_out = f"GOSIP_{ip}_OUT"

    rules = [
        f"nft insert rule {NFT_TABLE} {NFT_CHAIN} meta l4proto tcp ip saddr {ip} counter drop comment '\\\"!fw4: {tag_in}\\\"'",
        f"nft insert rule {NFT_TABLE} {NFT_CHAIN} meta l4proto udp ip saddr {ip} counter drop comment '\\\"!fw4: {tag_in}\\\"'",
        f"nft insert rule {NFT_TABLE} {NFT_CHAIN} meta l4proto tcp ip daddr {ip} counter drop comment '\\\"!fw4: {tag_out}\\\"'",
        f"nft insert rule {NFT_TABLE} {NFT_CHAIN} meta l4proto udp ip daddr {ip} counter drop comment '\\\"!fw4: {tag_out}\\\"'",
    ]

    rules_ok = 0
    errors = []

    for rule_cmd in rules:
        success, _, stderr = _ssh_exec(rule_cmd)
        if success:
            rules_ok += 1
        else:
            errors.append(stderr)

    # Matar conexiones activas
    _ssh_exec(f"conntrack -D -s {ip} 2>/dev/null")
    _ssh_exec(f"conntrack -D -d {ip} 2>/dev/null")

    if rules_ok == 4:
        _register_block(ip, ttl_hours)
        ttl_msg = f" (TTL: {ttl_hours}h)" if ttl_hours > 0 else " (permanente)"
        print(f"🔒 [FW] IP {ip} bloqueada — {rules_ok} reglas creadas{ttl_msg}")
        return {
            'success': True,
            'message': f'IP {ip} bloqueada exitosamente{ttl_msg}',
            'rules_created': rules_ok
        }
    elif rules_ok > 0:
        _register_block(ip, ttl_hours)
        print(f"⚠️ [FW] IP {ip} bloqueada parcialmente — {rules_ok}/4 reglas")
        return {
            'success': True,
            'message': f'Bloqueo parcial: {rules_ok}/4 reglas. Errores: {errors}',
            'rules_created': rules_ok
        }
    else:
        print(f"❌ [FW] Fallo al bloquear {ip}: {errors}")
        return {
            'success': False,
            'message': f'Error al bloquear: {errors}',
            'rules_created': 0
        }


def unblock_ip(ip):
    """
    Desbloquea una IP eliminando todas sus reglas del firewall.

    Returns:
        dict con 'success', 'message', 'rules_removed'
    """
    tag = f"GOSIP_{ip}"

    success, stdout, stderr = _ssh_exec(f"nft -a list chain {NFT_TABLE} {NFT_CHAIN}")
    if not success:
        return {
            'success': False,
            'message': f'Error listando reglas: {stderr}',
            'rules_removed': 0
        }

    handle_pattern = re.compile(rf'.*{tag}.*# handle (\d+)')
    handles = handle_pattern.findall(stdout)

    if not handles:
        _unregister_block(ip)
        return {
            'success': False,
            'message': f'No se encontraron reglas para {ip}',
            'rules_removed': 0
        }

    removed = 0
    for handle in handles:
        ok, _, err = _ssh_exec(f"nft delete rule {NFT_TABLE} {NFT_CHAIN} handle {handle}")
        if ok:
            removed += 1
        else:
            print(f"⚠️ [FW] Error eliminando handle {handle}: {err}")

    _unregister_block(ip)
    print(f"🔓 [FW] IP {ip} desbloqueada — {removed} reglas eliminadas")

    return {
        'success': True,
        'message': f'IP {ip} desbloqueada — {removed} reglas eliminadas',
        'rules_removed': removed
    }


def get_blocked_list():
    """
    Retorna la lista de IPs bloqueadas con metadata.

    Returns:
        dict {ip: {blocked_at, ttl_hours, time_remaining}}
    """
    with _registry_lock:
        registry = _load_registry()

    result = {}
    now = time.time()

    for ip, data in registry.items():
        ttl = data.get('ttl_hours', 0)
        blocked_ts = data.get('blocked_ts', now)

        if ttl > 0:
            expires_at = blocked_ts + (ttl * 3600)
            remaining_s = max(0, expires_at - now)
            remaining_h = remaining_s / 3600
            time_remaining = f"{remaining_h:.1f}h"
        else:
            time_remaining = "permanente"

        result[ip] = {
            'blocked_at': data.get('blocked_at', 'N/A'),
            'ttl_hours': ttl,
            'time_remaining': time_remaining
        }

    return result

# ==============================================================================
# LIMPIEZA AUTOMÁTICA
# ==============================================================================

def cleanup_expired():
    """Revisa el registro y desbloquea IPs cuyo TTL ha expirado."""
    now = time.time()

    with _registry_lock:
        registry = _load_registry()

    expired = []
    for ip, data in registry.items():
        ttl = data.get('ttl_hours', 0)
        if ttl <= 0:
            continue
        blocked_ts = data.get('blocked_ts', now)
        if now >= blocked_ts + (ttl * 3600):
            expired.append(ip)

    for ip in expired:
        print(f"⏰ [FW] TTL expirado para {ip}, desbloqueando...")
        unblock_ip(ip)

    return expired


def _cleanup_worker():
    """Hilo daemon que ejecuta cleanup_expired() periódicamente."""
    print(f"🧹 [FW] Hilo de limpieza iniciado (cada {CLEANUP_INTERVAL}s)")
    while True:
        try:
            cleanup_expired()
        except Exception as e:
            print(f"❌ [FW] Error en limpieza: {e}")
        time.sleep(CLEANUP_INTERVAL)


def start_cleanup_thread():
    """Inicia el hilo de limpieza automática."""
    t = threading.Thread(target=_cleanup_worker, daemon=True)
    t.start()
    return t

# ==============================================================================
# TEST RÁPIDO
# ==============================================================================

if __name__ == '__main__':
    TEST_IP = '203.0.113.99'

    print("=" * 60)
    print("TEST: firewall_manager.py")
    print("=" * 60)

    print(f"\n[1] Bloqueando {TEST_IP}...")
    result = block_ip(TEST_IP, ttl_hours=1)
    print(f"    Resultado: {result}")

    print(f"\n[2] ¿Está bloqueada? {is_blocked(TEST_IP)}")

    print(f"\n[3] Lista de bloqueadas:")
    for ip, data in get_blocked_list().items():
        print(f"    {ip}: {data}")

    print(f"\n[4] Desbloqueando {TEST_IP}...")
    result = unblock_ip(TEST_IP)
    print(f"    Resultado: {result}")

    print(f"\n[5] ¿Está bloqueada? {is_blocked(TEST_IP)}")

    print("\n" + "=" * 60)
    print("TEST COMPLETO")
    print("=" * 60)
