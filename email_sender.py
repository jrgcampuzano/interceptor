# -*- coding: utf-8 -*-
"""
INTERCEPTOR — Módulo de envío de correo
Basado en SPECTRE Email Sender.
Configuración vía variables de ambiente con prefijo SPECTRE_.
"""
import os
import smtplib
import datetime
from email.mime.text import MIMEText
from email.header import Header

# ==============================================================================
# CONFIGURACIÓN SMTP (variables de ambiente)
# ==============================================================================
EMAIL_TO = os.environ.get("SPECTRE_EMAIL_TO", "")
EMAIL_FROM = os.environ.get("SPECTRE_EMAIL_FROM", "")
SMTP_SERVER = os.environ.get("SPECTRE_SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SPECTRE_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SPECTRE_SMTP_USER", "")
SMTP_PASS = os.environ.get("SPECTRE_SMTP_PASS", "")
LOG_FILE = os.environ.get("SPECTRE_LOG_FILE", "/var/log/interceptor.log")


def write_log(message):
    """Escribe un mensaje en el log."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(log_message + '\n')
    except Exception as e:
        print(f"Error al escribir en el log: {e}")
        print(log_message)


def send_email_report(subject, html_body):
    """Envía un correo con el reporte en formato HTML."""
    missing = []
    if not EMAIL_TO:
        missing.append("SPECTRE_EMAIL_TO")
    if not EMAIL_FROM:
        missing.append("SPECTRE_EMAIL_FROM")
    if not SMTP_USER:
        missing.append("SPECTRE_SMTP_USER")
    if not SMTP_PASS:
        missing.append("SPECTRE_SMTP_PASS")

    if missing:
        write_log(f"[ERROR] Variables de ambiente faltantes: {', '.join(missing)}")
        return False

    msg = MIMEText(html_body, 'html', 'utf-8')
    msg['Subject'] = Header(subject, 'utf-8')
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        server.quit()
        write_log("Correo enviado con éxito.")
        return True
    except Exception as e:
        write_log(f"[ERROR] Error al enviar correo (SMTP): {e}")
        return False
