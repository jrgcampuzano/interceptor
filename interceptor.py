# -*- coding: utf-8 -*-
"""
INTERCEPTOR — Monitor de tráfico CCTV con bloqueo automático
Inspirado en el agente 007.

Componentes:
    1. Monitor de tráfico (tcpdump via socket)
    2. Bloqueo automático de IPs externas (nftables via SSH)
    3. Alertas por correo con links de acción
    4. Servidor Flask de control

Requiere:
    - Variables de ambiente SPECTRE_* para SMTP
    - SSH con llave pública al router
    - GeoLite2-City.mmdb para geolocalización
"""

import os
import sys
import time
import queue
import socket
import threading
from datetime import datetime

from flask import Flask, jsonify

# ==============================================================================
# IMPORTS LOCALES
# ==============================================================================
from config import (
    LISTEN_HOST, LISTEN_PORT, FLASK_HOST, FLASK_PORT,
    CCTV_IP, BASE_URL, AGGREGATION_TIME, THROTTLE_TIME,
    SILENCE_DURATION, SILENCE_STATUS_FILE, GEOIP_DATABASE,
    IP_IGNORE_LIST, BLOCKED_COUNTRY, IP_EXTRACT_REGEX,
    LAST_ALERT_TIME, DEFAULT_BLOCK_TTL_HOURS, LOG_FILE
)

from email_sender import send_email_report, write_log

from firewall_manager import (
    block_ip, unblock_ip, is_blocked,
    get_blocked_list, start_cleanup_thread
)

# ==============================================================================
# GEOIP
# ==============================================================================
try:
    import geoip2.database
    geoip_reader = geoip2.database.Reader(GEOIP_DATABASE)
    print(f"🌍 [GeoIP] Base de datos cargada: {GEOIP_DATABASE}")
except Exception as e:
    geoip_reader = None
    print(f"⚠️ [GeoIP] No disponible: {e}")

# ==============================================================================
# COLA DE ALERTAS
# ==============================================================================
alert_queue = queue.Queue()

# ==============================================================================
# FLASK APP
# ==============================================================================
app = Flask(__name__)


@app.route('/status')
def status():
    """Estado general del servicio."""
    silenced, end_time = is_silence_active()
    blocked = get_blocked_list()
    return jsonify({
        'service': 'interceptor',
        'status': 'running',
        'silenced': silenced,
        'silence_until': end_time,
        'blocked_ips': len(blocked),
        'blocked_list': blocked
    })


@app.route('/silence')
def silence():
    """Silencia alertas por 15 minutos."""
    end_ts = time.time() + SILENCE_DURATION
    try:
        with open(SILENCE_STATUS_FILE, 'w') as f:
            f.write(str(end_ts))
        end_str = datetime.fromtimestamp(end_ts).strftime('%H:%M:%S')
        write_log(f"Alertas silenciadas hasta {end_str}")
        return jsonify({
            'success': True,
            'message': f'Alertas silenciadas hasta {end_str}'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/stop_service')
def stop_service():
    """Detiene el servicio (sale del proceso)."""
    write_log("Servicio detenido vía endpoint /stop_service")
    func = lambda: (time.sleep(1), os._exit(0))
    threading.Thread(target=func, daemon=True).start()
    return jsonify({'success': True, 'message': 'Servicio deteniendo...'})


@app.route('/start_service')
def start_service():
    """Placeholder — el servicio se inicia ejecutando el script."""
    return jsonify({
        'success': True,
        'message': 'El servicio ya está corriendo. Para reiniciar, use systemctl o ejecute el script.'
    })


@app.route('/block/<ip>')
def block_endpoint(ip):
    """Bloquea una IP manualmente vía HTTP."""
    result = block_ip(ip, ttl_hours=DEFAULT_BLOCK_TTL_HOURS)
    write_log(f"Bloqueo manual vía HTTP: {ip} -> {result['message']}")
    return jsonify(result)


@app.route('/block/<ip>/<int:ttl>')
def block_endpoint_ttl(ip, ttl):
    """Bloquea una IP con TTL personalizado."""
    result = block_ip(ip, ttl_hours=ttl)
    write_log(f"Bloqueo manual vía HTTP: {ip} (TTL:{ttl}h) -> {result['message']}")
    return jsonify(result)


@app.route('/unblock/<ip>')
def unblock_endpoint(ip):
    """Desbloquea una IP manualmente vía HTTP."""
    result = unblock_ip(ip)
    write_log(f"Desbloqueo manual vía HTTP: {ip} -> {result['message']}")
    return jsonify(result)


@app.route('/blocked')
def blocked_list():
    """Lista todas las IPs bloqueadas."""
    return jsonify(get_blocked_list())


def start_flask():
    """Inicia Flask en un hilo separado."""
    app.run(host=FLASK_HOST, port=FLASK_PORT, threaded=True)

# ==============================================================================
# FUNCIONES AUXILIARES
# ==============================================================================

def get_geoip_data(ip):
    """Obtiene datos de geolocalización para una IP."""
    if geoip_reader is None:
        return {"country": "GeoIP Off", "coords": "N/A", "location_detail": "N/A"}

    if ip.startswith(('10.', '192.168.', '172.')):
        return {"country": "Local", "coords": "N/A", "location_detail": "Red Interna"}

    try:
        res = geoip_reader.city(ip)
        country = res.country.name or "Desconocido"
        coords = f"{res.location.latitude:.4f}, {res.location.longitude:.4f}"
        city = res.city.name or ""
        region = res.subdivisions.most_specific.name or ""
        location_detail = f"{city}, {region}".strip(", ")
        return {
            "country": country,
            "coords": coords,
            "location_detail": location_detail or "N/A"
        }
    except Exception:
        return {"country": "Desconocido", "coords": "N/A", "location_detail": "N/A"}


def is_silence_active():
    """Verifica si el modo silencio está activo."""
    if not os.path.exists(SILENCE_STATUS_FILE):
        return False, None
    try:
        with open(SILENCE_STATUS_FILE, 'r') as f:
            ts = float(f.read().strip())
        if time.time() < ts:
            return True, datetime.fromtimestamp(ts).strftime('%H:%M:%S')
        os.remove(SILENCE_STATUS_FILE)
    except Exception:
        pass
    return False, None

# ==============================================================================
# PROCESAMIENTO DE LOGS
# ==============================================================================

def parse_log_line(line):
    """Parsea una línea de tcpdump y retorna datos estructurados o None."""
    match = IP_EXTRACT_REGEX.search(line)
    if not match:
        return None

    try:
        src_ip = match.group(1)
        src_port = int(match.group(2))
        dst_ip = match.group(3)
        dst_port = int(match.group(4))
        protocol = match.group(5).split(',')[0]

        is_outgoing = (src_ip == CCTV_IP)
        remote_ip = dst_ip if is_outgoing else src_ip
        port = dst_port if is_outgoing else src_port

        # Filtrar IPs ignoradas y rangos internos no relevantes
        if remote_ip in IP_IGNORE_LIST or remote_ip.startswith(('10.', '172.')):
            return None

        geo = get_geoip_data(remote_ip)

        # Filtrar tráfico saliente a país bloqueado
        if is_outgoing and geo['country'] == BLOCKED_COUNTRY:
            return None

        return {
            'timestamp': datetime.now().isoformat(),
            'remote_ip': remote_ip,
            'is_outgoing': is_outgoing,
            'protocol': protocol,
            'port': port,
            'country': geo['country'],
            'coords': geo['coords'],
            'location_detail': geo['location_detail'],
            'was_blocked': False
        }
    except Exception:
        return None

# ==============================================================================
# ENVÍO DE ALERTAS POR CORREO
# ==============================================================================

def build_email_html(log_entries):
    """Construye el HTML del correo de alerta con links de acción."""
    summary_lines = []
    seen = set()
    blocked_ips_in_batch = []

    for d in log_entries:
        flow = "⬆️ SALIDA" if d['is_outgoing'] else "⬇️ ENTRADA"
        key = (flow, d['remote_ip'])
        if key in seen:
            continue
        seen.add(key)

        blocked_tag = ' 🔒 <b style="color:red;">BLOQUEADA</b>' if d.get('was_blocked') else ''
        line = (
            f"[{d['timestamp'][11:19]}] <b>{flow}</b> | "
            f"IP: {d['remote_ip']}:{d['port']} | "
            f"{d['country']} ({d['location_detail']}){blocked_tag}"
        )
        summary_lines.append(line)

        if d.get('was_blocked'):
            blocked_ips_in_batch.append(d['remote_ip'])

    alerts_html = "<br>".join(summary_lines)

    # Botones de acción por cada IP bloqueada
    unblock_buttons = ""
    if blocked_ips_in_batch:
        buttons = []
        for ip in set(blocked_ips_in_batch):
            btn = (
                f'<a href="{BASE_URL}/unblock/{ip}" '
                f'style="background:#5cb85c; color:white; padding:8px 12px; '
                f'text-decoration:none; border-radius:5px; margin:2px;">'
                f'🔓 Desbloquear {ip}</a>'
            )
            buttons.append(btn)
        unblock_buttons = "<br><br><b>Acciones de desbloqueo:</b><br>" + " ".join(buttons)

    html = f"""
    <html><body>
        <h3>🛡️ Interceptor — Alerta de Tráfico CCTV</h3>
        <pre style="background:#f4f4f4; padding:10px; font-size:13px;">{alerts_html}</pre>
        {unblock_buttons}
        <hr>
        <p>
            <a href="{BASE_URL}/silence"
               style="background:#f0ad4e; color:white; padding:10px 15px;
                      text-decoration:none; border-radius:5px;">
                🔇 Silenciar 15m</a>
            &nbsp;
            <a href="{BASE_URL}/blocked"
               style="background:#337ab7; color:white; padding:10px 15px;
                      text-decoration:none; border-radius:5px;">
                📋 Ver bloqueadas</a>
            &nbsp;
            <a href="{BASE_URL}/stop_service"
               style="background:#d9534f; color:white; padding:10px 15px;
                      text-decoration:none; border-radius:5px;">
                🔴 Detener</a>
        </p>
    </body></html>
    """
    return html, len(summary_lines)


def email_worker():
    """Hilo que procesa la cola de correos."""
    print("📧 [EmailWorker] Hilo de envío iniciado...")
    while True:
        try:
            logs_to_send = alert_queue.get()
            if logs_to_send:
                html, count = build_email_html(logs_to_send)
                subject = f"🛡️ Interceptor: {count} eventos detectados"
                print(f"📧 [EmailWorker] Enviando alerta con {count} eventos...")
                send_email_report(subject, html)
            alert_queue.task_done()
        except Exception as e:
            print(f"❌ [EmailWorker] Error: {e}")
            write_log(f"[ERROR] EmailWorker: {e}")
            time.sleep(2)

# ==============================================================================
# MONITOR PRINCIPAL
# ==============================================================================

def monitor_syslog():
    """Loop principal: recibe tráfico por socket, analiza, bloquea y alerta."""
    print(f"📡 [Monitor] Escuchando en {LISTEN_HOST}:{LISTEN_PORT}...")

    collected_logs = []
    last_email_time = time.time()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        s.bind((LISTEN_HOST, LISTEN_PORT))
        s.listen(1)

        while True:
            # Verificar silencio
            is_silenced, end_time = is_silence_active()
            if is_silenced:
                print(f"🔇 [Monitor] Silencio activo hasta {end_time}...")
                time.sleep(30)
                continue

            try:
                conn, addr = s.accept()
                with conn:
                    with conn.makefile('r') as conn_file:
                        for line in conn_file:
                            if not line:
                                continue

                            data = parse_log_line(line)
                            if not data:
                                continue

                            rip = data['remote_ip']

                            # ── BLOQUEO AUTOMÁTICO ──
                            if data['country'] != 'Local' and not is_blocked(rip):
                                block_result = block_ip(rip, ttl_hours=DEFAULT_BLOCK_TTL_HOURS)
                                if block_result['success']:
                                    data['was_blocked'] = True
                                    write_log(
                                        f"BLOQUEO AUTO: {rip} | "
                                        f"{data['country']} ({data['location_detail']}) | "
                                        f"TTL: {DEFAULT_BLOCK_TTL_HOURS}h"
                                    )
                            # ── FIN BLOQUEO ──

                            # Throttle por IP
                            if time.time() - LAST_ALERT_TIME[rip] > THROTTLE_TIME:
                                collected_logs.append(data)
                                LAST_ALERT_TIME[rip] = time.time()

                            # Enviar lote acumulado
                            if collected_logs and (time.time() - last_email_time) >= AGGREGATION_TIME:
                                if not is_silence_active()[0]:
                                    alert_queue.put(list(collected_logs))
                                collected_logs = []
                                last_email_time = time.time()

            except socket.error as e:
                print(f"⚠️ [Monitor] Error de socket: {e}")
                break

    except Exception as e:
        print(f"❌ [Monitor] Error fatal: {e}")
        write_log(f"[ERROR] Monitor: {e}")
    finally:
        s.close()

# ==============================================================================
# PUNTO DE ENTRADA
# ==============================================================================

def main():
    """Inicia todos los componentes de Interceptor."""
    print("=" * 60)
    print("  🛡️  INTERCEPTOR — Monitor de Tráfico CCTV")
    print("  Inspirado en el agente 007")
    print("=" * 60)
    print(f"  CCTV IP:    {CCTV_IP}")
    print(f"  Listener:   {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"  Flask:      {FLASK_HOST}:{FLASK_PORT}")
    print(f"  Block TTL:  {DEFAULT_BLOCK_TTL_HOURS}h")
    print("=" * 60)

    # Hilo: envío de correos
    threading.Thread(target=email_worker, daemon=True).start()

    # Hilo: limpieza de IPs expiradas
    start_cleanup_thread()

    # Hilo: servidor Flask
    threading.Thread(target=start_flask, daemon=True).start()

    # Loop principal: monitor de tráfico
    while True:
        try:
            monitor_syslog()
        except Exception as e:
            print(f"❌ [Main] Error en monitor, reiniciando en 5s: {e}")
            write_log(f"[ERROR] Main loop: {e}")
        time.sleep(5)


if __name__ == "__main__":
    main()
