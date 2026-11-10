#!/bin/bash
# Instala el sondeo de Microsoft Graph en Ubuntu (systemd timer + venv).
# Uso: sudo ./deploy/ubuntu/install.sh   (desde la raíz del proyecto copiado)
set -euo pipefail

APP_DIR=/opt/superphishing
APP_USER=superphishing
ENV_DIR=/etc/superphishing
SRC_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Ejecutar con sudo." >&2
  exit 1
fi

apt-get update -qq
apt-get install -y -qq python3 python3-venv rsync

id "$APP_USER" >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"

mkdir -p "$APP_DIR"
if [[ "$SRC_DIR" != "$APP_DIR" ]]; then
  rsync -a --delete \
    --exclude '.venv/' --exclude '.env' --exclude 'cases/' --exclude 'storage/' --exclude '.git/' \
    "$SRC_DIR/" "$APP_DIR/"
fi
mkdir -p "$APP_DIR/cases" "$APP_DIR/storage"

# Código de solo lectura para el servicio; escribe únicamente cases/ y storage/.
chown -R root:"$APP_USER" "$APP_DIR"
chmod -R u=rwX,g=rX,o= "$APP_DIR"
chown -R "$APP_USER":"$APP_USER" "$APP_DIR/cases" "$APP_DIR/storage"
chmod 0750 "$APP_DIR/cases" "$APP_DIR/storage"

if [[ ! -x "$APP_DIR/.venv/bin/python" ]]; then
  python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/python" -m pip install -q --upgrade pip
"$APP_DIR/.venv/bin/python" -m pip install -q -r "$APP_DIR/requirements.txt"
chown -R root:"$APP_USER" "$APP_DIR/.venv"

mkdir -p "$ENV_DIR"
if [[ ! -f "$ENV_DIR/graph.env" ]]; then
  install -m 0640 -o root -g "$APP_USER" "$APP_DIR/deploy/ubuntu/graph.env.example" "$ENV_DIR/graph.env"
  echo "Edita $ENV_DIR/graph.env con las credenciales antes de activar el timer."
fi

install -m 0644 "$APP_DIR/deploy/ubuntu/superphishing-graph.service" /etc/systemd/system/
install -m 0644 "$APP_DIR/deploy/ubuntu/superphishing-graph.timer" /etc/systemd/system/
systemctl daemon-reload

echo "Instalado. Para activar el sondeo:"
echo "  sudo systemctl start superphishing-graph.service   # prueba manual"
echo "  journalctl -u superphishing-graph.service -n 50"
echo "  sudo systemctl enable --now superphishing-graph.timer"
