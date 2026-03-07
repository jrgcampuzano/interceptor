# -*- coding: utf-8 -*-
"""
INTERCEPTOR — Monitor de tráfico CCTV con bloqueo automático

Componentes:
    1. Monitor de tráfico (tcpdump via socket)
    2. Bloqueo automático de IPs externas (nftables via SSH)
    3. Alertas por correo con tokens de un solo uso
    4. Servidor Flask con JWT + Dashboard web
"""

import os, sys, time, json, queue, socket, secrets, functools, threading
from datetime import datetime, timedelta

import jwt
from flask import Flask, jsonify, request, make_response, send_from_directory

from config import (
    LISTEN_HOST, LISTEN_PORT, FLASK_HOST, FLASK_PORT,
    CCTV_IP, BASE_URL, AGGREGATION_TIME, THROTTLE_TIME,
    SILENCE_DURATION, SILENCE_STATUS_FILE, GEOIP_DATABASE,
    IP_IGNORE_LIST, BLOCKED_COUNTRY, IP_EXTRACT_REGEX,
    LAST_ALERT_TIME, DEFAULT_BLOCK_TTL_HOURS, LOG_FILE,
    ALLOWED_IPS, BASE_DIR
)
from email_sender import send_email_report, write_log
from firewall_manager import (
    block_ip, unblock_ip, is_blocked,
    get_blocked_list, start_cleanup_thread
)

# ══════════════════════════════════════════════════════════════
#  JWT CONFIG
# ══════════════════════════════════════════════════════════════
API_SECRET = os.getenv("API_SECRET", "")
API_USER = os.getenv("API_USER", "admin")
API_PASS = os.getenv("API_PASS", "")
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "24"))
API_PUBLIC_URL = os.getenv("API_PUBLIC_URL", BASE_URL)

if not API_SECRET:
    print("⚠️  API_SECRET no configurado.")

# ══════════════════════════════════════════════════════════════
#  GEOIP
# ══════════════════════════════════════════════════════════════
try:
    import geoip2.database
    geoip_reader = geoip2.database.Reader(GEOIP_DATABASE)
    print(f"🌍 [GeoIP] Cargada: {GEOIP_DATABASE}")
except Exception as e:
    geoip_reader = None
    print(f"⚠️ [GeoIP] No disponible: {e}")

alert_queue = queue.Queue()

# ══════════════════════════════════════════════════════════════
#  EMAIL ACTION TOKENS (un solo uso, 1h)
# ══════════════════════════════════════════════════════════════
_email_tokens = {}

def create_email_action_token(action, ip=None):
    token = secrets.token_urlsafe(32)
    _email_tokens[token] = {"action": action, "ip": ip, "expires": time.time() + 3600}
    expired = [k for k, v in _email_tokens.items() if time.time() > v["expires"]]
    for k in expired:
        del _email_tokens[k]
    return token

# ══════════════════════════════════════════════════════════════
#  ALLOWED IPS
# ══════════════════════════════════════════════════════════════
ALLOWED_IPS_FILE = os.path.join(BASE_DIR, 'allowed_ips.json')

def _load_allowed_ips():
    if os.path.exists(ALLOWED_IPS_FILE):
        try:
            with open(ALLOWED_IPS_FILE, 'r') as f:
                data = json.load(f)
                ALLOWED_IPS.update(data.keys() if isinstance(data, dict) else data)
        except Exception: pass

def _save_allowed_ips():
    try:
        data = {}
        if os.path.exists(ALLOWED_IPS_FILE):
            try:
                with open(ALLOWED_IPS_FILE, 'r') as f: data = json.load(f)
            except Exception: pass
        for ip in ALLOWED_IPS:
            if ip not in data: data[ip] = {'allowed_at': datetime.now().isoformat()}
        data = {ip: v for ip, v in data.items() if ip in ALLOWED_IPS}
        with open(ALLOWED_IPS_FILE, 'w') as f: json.dump(data, f, indent=2)
    except Exception as e:
        print(f"⚠️ [Allow] Error: {e}")

def allow_ip(ip):
    if is_blocked(ip): unblock_ip(ip)
    ALLOWED_IPS.add(ip)
    _save_allowed_ips()
    write_log(f"IP PERMITIDA: {ip}")
    return {'success': True, 'message': f'IP {ip} permitida'}

def disallow_ip(ip):
    ALLOWED_IPS.discard(ip)
    _save_allowed_ips()
    write_log(f"IP REVOCADA: {ip}")
    return {'success': True, 'message': f'IP {ip} revocada'}

# ══════════════════════════════════════════════════════════════
#  FLASK APP
# ══════════════════════════════════════════════════════════════
app = Flask(__name__, static_folder="static")

def create_token(username):
    payload = {"sub": username, "iat": datetime.utcnow(),
               "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)}
    return jwt.encode(payload, API_SECRET, algorithm="HS256")

def token_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Token requerido"}), 401
        try:
            tok = auth.split(" ", 1)[1]
            payload = jwt.decode(tok, API_SECRET, algorithms=["HS256"])
            request.user = payload["sub"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido"}), 401
        return f(*args, **kwargs)
    return wrapper

@app.route("/")
def dashboard():
    return send_from_directory(app.static_folder, "dashboard.html")

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    if data.get("username") == API_USER and data.get("password") == API_PASS:
        return jsonify({"token": create_token(API_USER), "expires_in": f"{JWT_EXPIRY_HOURS}h"})
    return jsonify({"error": "Credenciales inválidas"}), 401

@app.route("/api/status")
@token_required
def status():
    silenced, end_time = is_silence_active()
    blocked = get_blocked_list()
    return jsonify({
        'service': 'interceptor', 'status': 'silenced' if silenced else 'running',
        'silenced': silenced, 'silence_until': end_time,
        'blocked_ips': len(blocked), 'blocked_list': blocked,
        'allowed_ips': list(ALLOWED_IPS),
        'server_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'block_ttl_hours': DEFAULT_BLOCK_TTL_HOURS, 'cctv_ip': CCTV_IP,
    })

@app.route("/api/silence", methods=["POST"])
@token_required
def silence():
    data = request.get_json(silent=True) or {}
    minutes = data.get("minutes", 15)
    end_ts = time.time() + (minutes * 60)
    with open(SILENCE_STATUS_FILE, 'w') as f: f.write(str(end_ts))
    until = datetime.fromtimestamp(end_ts).strftime('%H:%M:%S')
    write_log(f"Silenciado {minutes}min hasta {until}")
    return jsonify({'success': True, 'until': until})

@app.route("/api/resume", methods=["POST"])
@token_required
def resume():
    if os.path.exists(SILENCE_STATUS_FILE):
        os.remove(SILENCE_STATUS_FILE)
        return jsonify({"status": "resumed"})
    return jsonify({"status": "already_active"})

@app.route("/api/block/<ip>", methods=["POST"])
@token_required
def api_block(ip):
    data = request.get_json(silent=True) or {}
    result = block_ip(ip, ttl_hours=data.get("ttl_hours", DEFAULT_BLOCK_TTL_HOURS))
    write_log(f"Bloqueo manual: {ip}")
    return jsonify(result)

@app.route("/api/unblock/<ip>", methods=["POST"])
@token_required
def api_unblock(ip):
    result = unblock_ip(ip)
    write_log(f"Desbloqueo manual: {ip}")
    return jsonify(result)

@app.route("/api/allow/<ip>", methods=["POST"])
@token_required
def api_allow(ip):
    return jsonify(allow_ip(ip))

@app.route("/api/disallow/<ip>", methods=["POST"])
@token_required
def api_disallow(ip):
    return jsonify(disallow_ip(ip))

@app.route("/api/blocked")
@token_required
def api_blocked():
    return jsonify(get_blocked_list())

@app.route("/api/allowed")
@token_required
def api_allowed():
    return jsonify(list(ALLOWED_IPS))

@app.route("/api/stop", methods=["POST"])
@token_required
def api_stop():
    write_log("Servicio detenido vía API")
    threading.Thread(target=lambda: (time.sleep(1), os._exit(0)), daemon=True).start()
    return jsonify({'success': True, 'message': 'Deteniendo...'})

# ── Email Action Pages ──
@app.route("/action/<action_type>")
def email_action_confirm(action_type):
    token = request.args.get("token", "")
    if token not in _email_tokens:
        return make_response(_action_page("Token inválido", "Enlace usado o expirado.", success=False)), 400
    info = _email_tokens[token]
    if time.time() > info["expires"]:
        del _email_tokens[token]
        return make_response(_action_page("Enlace expirado", "Usa uno de un email más reciente.", success=False)), 400
    ip = info.get("ip", "")
    titles = {"unblock": f"Desbloquear {ip}", "allow": f"Permitir {ip}", "silence": "Silenciar 15 min"}
    return make_response(_action_page(
        titles.get(info["action"], action_type), "¿Confirmas esta acción?",
        confirm_url=f"/action/{action_type}/confirm?token={token}", success=None))

@app.route("/action/<action_type>/confirm")
def email_action_execute(action_type):
    token = request.args.get("token", "")
    if token not in _email_tokens:
        return make_response(_action_page("Token inválido", "Enlace usado o expirado.", success=False)), 400
    info = _email_tokens.pop(token)
    if time.time() > info["expires"]:
        return make_response(_action_page("Enlace expirado", "Enlace expirado.", success=False)), 400
    ip, action = info.get("ip", ""), info.get("action", action_type)
    if action == "unblock":
        r = unblock_ip(ip); msg = f"IP {ip} desbloqueada. {r.get('rules_removed',0)} reglas eliminadas."
    elif action == "allow":
        allow_ip(ip); msg = f"IP {ip} permitida. Acceso al CCTV habilitado."
    elif action == "silence":
        end_ts = time.time() + SILENCE_DURATION
        with open(SILENCE_STATUS_FILE, 'w') as f: f.write(str(end_ts))
        msg = f"Alertas silenciadas hasta {datetime.fromtimestamp(end_ts).strftime('%H:%M:%S')}."
    else:
        msg = f"Acción desconocida: {action}"
    return make_response(_action_page("Acción completada", msg, success=True))

def _action_page(title, message, success=None, confirm_url=None):
    if success is True: color, icon = "#22c55e", "✓"
    elif success is False: color, icon = "#ef4444", "✗"
    else: color, icon = "#3b82f6", "⏸"
    btn = ""
    if confirm_url:
        btn = f'<a href="{confirm_url}" style="display:inline-block;margin-top:20px;padding:14px 40px;background:{color};color:white;text-decoration:none;border-radius:8px;font-size:18px;font-weight:bold;">Confirmar</a><p style="margin-top:12px;color:#888;font-size:13px;">Enlace de un solo uso</p>'
    return f'''<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title></head><body style="margin:0;padding:40px 20px;font-family:-apple-system,system-ui,sans-serif;background:#0a0e1a;color:#e2e8f0;text-align:center;min-height:100vh;"><div style="max-width:480px;margin:0 auto;"><div style="font-size:64px;margin-bottom:16px;">{icon}</div><h1 style="color:{color};margin-bottom:8px;">{title}</h1><p style="font-size:16px;color:#94a3b8;line-height:1.6;">{message}</p>{btn}<p style="margin-top:40px;color:#475569;font-size:12px;">INTERCEPTOR</p></div></body></html>'''

def start_flask():
    app.run(host=FLASK_HOST, port=FLASK_PORT, threaded=True)

# ══════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════
def get_geoip_data(ip):
    if geoip_reader is None: return {"country":"GeoIP Off","coords":"N/A","location_detail":"N/A"}
    if ip.startswith(('10.','192.168.','172.')): return {"country":"Local","coords":"N/A","location_detail":"Red Interna"}
    try:
        res = geoip_reader.city(ip)
        return {"country": res.country.name or "Desconocido",
                "coords": f"{res.location.latitude:.4f}, {res.location.longitude:.4f}",
                "location_detail": f"{res.city.name or ''}, {res.subdivisions.most_specific.name or ''}".strip(", ") or "N/A"}
    except Exception: return {"country":"Desconocido","coords":"N/A","location_detail":"N/A"}

def is_silence_active():
    if not os.path.exists(SILENCE_STATUS_FILE): return False, None
    try:
        with open(SILENCE_STATUS_FILE,'r') as f: ts = float(f.read().strip())
        if time.time() < ts: return True, datetime.fromtimestamp(ts).strftime('%H:%M:%S')
        os.remove(SILENCE_STATUS_FILE)
    except Exception: pass
    return False, None

def parse_log_line(line):
    match = IP_EXTRACT_REGEX.search(line)
    if not match: return None
    try:
        src_ip, dst_ip = match.group(1), match.group(3)
        is_outgoing = (src_ip == CCTV_IP)
        remote_ip = dst_ip if is_outgoing else src_ip
        port = int(match.group(4)) if is_outgoing else int(match.group(2))
        protocol = match.group(5).split(',')[0]
        if remote_ip in IP_IGNORE_LIST or remote_ip.startswith(('10.','172.')): return None
        geo = get_geoip_data(remote_ip)
        if is_outgoing and geo['country'] == BLOCKED_COUNTRY: return None
        return {'timestamp': datetime.now().isoformat(), 'remote_ip': remote_ip,
                'is_outgoing': is_outgoing, 'protocol': protocol, 'port': port,
                'country': geo['country'], 'coords': geo['coords'],
                'location_detail': geo['location_detail'], 'was_blocked': False}
    except Exception: return None

# ══════════════════════════════════════════════════════════════
#  EMAIL ALERTS
# ══════════════════════════════════════════════════════════════
def build_email_html(log_entries):
    summary_lines, seen, ips = [], set(), set()
    for d in log_entries:
        flow = "⬆️ SALIDA" if d['is_outgoing'] else "⬇️ ENTRADA"
        key = (flow, d['remote_ip'])
        if key in seen: continue
        seen.add(key)
        tag = ' 🔒 <b style="color:#ef4444;">BLOQUEADA</b>' if d.get('was_blocked') else ''
        summary_lines.append(f"[{d['timestamp'][11:19]}] <b>{flow}</b> | IP: {d['remote_ip']}:{d['port']} | {d['country']} ({d['location_detail']}){tag}")
        ips.add(d['remote_ip'])

    bs = "display:inline-block;padding:8px 16px;margin:4px;text-decoration:none;border-radius:6px;font-weight:bold;font-size:13px;color:white;"
    btns = []
    for ip in ips:
        btns.append(f'<a href="{API_PUBLIC_URL}/action/unblock?token={create_email_action_token("unblock",ip)}" style="{bs}background:#22c55e;">🔓 Desbloquear {ip}</a>')
        btns.append(f'<a href="{API_PUBLIC_URL}/action/allow?token={create_email_action_token("allow",ip)}" style="{bs}background:#3b82f6;">✅ Permitir {ip}</a>')

    silence_tok = create_email_action_token("silence")
    html = f'''<html><body style="font-family:-apple-system,system-ui,sans-serif;background:#0a0e1a;color:#e2e8f0;padding:20px;">
    <div style="max-width:600px;margin:0 auto;background:#111827;border-radius:12px;padding:24px;border:1px solid #1e3a5f;">
    <h2 style="margin-top:0;color:#3b82f6;">🛡️ Interceptor</h2>
    <pre style="background:#0a0e1a;padding:14px;border-radius:8px;font-size:13px;line-height:1.8;overflow-x:auto;color:#e2e8f0;">{"<br>".join(summary_lines)}</pre>
    <br><b>Acciones:</b><br>{" ".join(btns)}
    <hr style="border:none;border-top:1px solid #1e3a5f;margin:20px 0;">
    <a href="{API_PUBLIC_URL}/action/silence?token={silence_tok}" style="{bs}background:#f59e0b;">🔇 Silenciar 15m</a>
    <a href="{API_PUBLIC_URL}" style="{bs}background:#6b7280;">📊 Dashboard</a>
    </div></body></html>'''
    return html, len(summary_lines)

def email_worker():
    print("📧 [EmailWorker] Iniciado...")
    while True:
        try:
            logs = alert_queue.get()
            if logs:
                html, n = build_email_html(logs)
                print(f"📧 [EmailWorker] Enviando {n} eventos...")
                send_email_report(f"🛡️ Interceptor: {n} eventos", html)
            alert_queue.task_done()
        except Exception as e:
            print(f"❌ [EmailWorker] {e}")
            time.sleep(2)

# ══════════════════════════════════════════════════════════════
#  MONITOR
# ══════════════════════════════════════════════════════════════
def monitor_syslog():
    print(f"📡 [Monitor] Escuchando en {LISTEN_HOST}:{LISTEN_PORT}...")
    collected, last_t, first = [], time.time(), False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((LISTEN_HOST, LISTEN_PORT)); s.listen(1)
        while True:
            sil, et = is_silence_active()
            if sil: print(f"🔇 Silencio hasta {et}..."); time.sleep(30); continue
            try:
                conn, addr = s.accept()
                print(f"🔗 Conexión desde {addr}")
                with conn, conn.makefile('r') as cf:
                    for line in cf:
                        if not line: continue
                        data = parse_log_line(line)
                        if not data: continue
                        rip = data['remote_ip']
                        if rip in ALLOWED_IPS: continue
                        if data['country'] != 'Local' and not is_blocked(rip):
                            br = block_ip(rip, ttl_hours=DEFAULT_BLOCK_TTL_HOURS)
                            if br['success']:
                                data['was_blocked'] = True
                                write_log(f"BLOQUEO: {rip} | {data['country']} | TTL:{DEFAULT_BLOCK_TTL_HOURS}h")
                        if time.time() - LAST_ALERT_TIME[rip] > THROTTLE_TIME:
                            collected.append(data); LAST_ALERT_TIME[rip] = time.time()
                            if not first:
                                if not is_silence_active()[0]:
                                    print("⚡ Primera detección — envío inmediato")
                                    alert_queue.put(list(collected)); collected = []; last_t = time.time(); first = True
                                continue
                        if collected and (time.time() - last_t) >= AGGREGATION_TIME:
                            if not is_silence_active()[0]:
                                print(f"📦 Lote: {len(collected)} eventos")
                                alert_queue.put(list(collected))
                            collected = []; last_t = time.time()
            except socket.error as e: print(f"⚠️ Socket: {e}"); break
    except Exception as e: print(f"❌ Fatal: {e}"); write_log(f"[ERROR] Monitor: {e}")
    finally: s.close()

def main():
    print("="*60)
    print("  🛡️  INTERCEPTOR")
    print("="*60)
    print(f"  CCTV:     {CCTV_IP}")
    print(f"  Listen:   {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"  Flask:    {FLASK_HOST}:{FLASK_PORT}")
    print(f"  Public:   {API_PUBLIC_URL}")
    print(f"  TTL:      {DEFAULT_BLOCK_TTL_HOURS}h")
    print(f"  Auth:     {'✓' if API_SECRET else '✗'}")
    print("="*60)
    _load_allowed_ips()
    if ALLOWED_IPS: print(f"✅ Permitidas: {ALLOWED_IPS}")
    threading.Thread(target=email_worker, daemon=True).start()
    start_cleanup_thread()
    threading.Thread(target=start_flask, daemon=True).start()
    while True:
        try: monitor_syslog()
        except Exception as e: print(f"❌ {e}"); write_log(f"[ERROR] {e}")
        time.sleep(5)

if __name__ == "__main__":
    main()
