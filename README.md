# 🛡️ Interceptor

Monitor de tráfico CCTV con bloqueo automático de IPs en firewall.

## Arquitectura

```
[Router OpenWrt] --tcpdump+ncat:5555--> [Raspberry Pi]
                                            │
                                     interceptor.py
                                       ├── Analiza tráfico
                                       ├── Bloquea IPs externas (SSH → nftables)
                                       ├── Envía alertas por correo
                                       └── Servidor Flask de control (:5558)
```

## Componentes

| Archivo              | Función                                      |
|----------------------|----------------------------------------------|
| `interceptor.py`     | Script principal: monitor + Flask + alertas   |
| `firewall_manager.py`| Módulo de bloqueo nftables vía SSH            |
| `email_sender.py`    | Módulo de envío de correo (SMTP)              |
| `config.py`          | Configuración centralizada                    |

## Requisitos

- Raspberry Pi con Python 3.9+
- Router OpenWrt 22+ (fw4/nftables)
- SSH con llave pública al router
- Base de datos GeoLite2-City.mmdb
- Variables de ambiente SPECTRE_* para SMTP

## Instalación

```bash
git clone https://github.com/jrgcampuzano/interceptor.git
cd interceptor
pip install -r requirements.txt
cp .env.example .env
# Editar .env con credenciales reales
# Copiar GeoLite2-City.mmdb al directorio
```

## Uso

```bash
export $(cat .env | xargs)
python3 interceptor.py
```

## Endpoints Flask (puerto 5558)

| Ruta                  | Acción                              |
|-----------------------|-------------------------------------|
| `/status`             | Estado general del servicio         |
| `/silence`            | Silenciar alertas 15 min            |
| `/stop_service`       | Detener el servicio                 |
| `/start_service`      | Info de inicio                      |
| `/block/<ip>`         | Bloquear IP (TTL default: 24h)      |
| `/block/<ip>/<ttl>`   | Bloquear IP con TTL personalizado   |
| `/unblock/<ip>`       | Desbloquear IP                      |
| `/blocked`            | Listar IPs bloqueadas               |

## Router (OpenWrt)

El tcpdump se ejecuta en el router y envía datos a la RPi:

```bash
tcpdump -i br-lan host 192.168.3.58 -l -n | ncat 192.168.3.7 5555
```
