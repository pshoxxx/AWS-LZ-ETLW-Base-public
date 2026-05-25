#!/bin/bash
# Web Spoke EC2 bootstrap.
# Python3 is pre-installed on Amazon Linux 2023 -- no internet required to run.
set -e

mkdir -p /var/www/html

# IMDSv2 token + AZ lookup. http_tokens=required on the instance forces v2.
TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
AZ=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/placement/availability-zone)

# Image is hosted in the repo and loaded by the visitor's browser from
# raw.githubusercontent.com -- the EC2 itself only serves HTML and does
# not need any internet egress to GitHub.
IMG_URL="https://raw.githubusercontent.com/pshoxxx/AWS-LZ-ETLW-Base/main/assets/duckling-comic.png"

cat > /var/www/html/index.html <<HTML
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Web Spoke - $AZ</title>
    <style>
      body { font-family: sans-serif; max-width: 1280px; margin: 2rem auto; padding: 0 1rem; }
      h1 { margin-bottom: 1rem; }
      img { max-width: 100%; height: auto; display: block; }
    </style>
  </head>
  <body>
    <h1>Web Spoke - AWS Landing Zone - $AZ</h1>
    <img src="$IMG_URL" alt="Ducklings on a mission" />
  </body>
</html>
HTML

cat > /etc/systemd/system/webserver.service <<UNIT
[Unit]
Description=Web Spoke Static Server
After=network.target
[Service]
ExecStart=/usr/bin/python3 -m http.server 80 --directory /var/www/html
Restart=always
User=root
[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable webserver
systemctl start webserver
