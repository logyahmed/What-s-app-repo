@echo off
chcp 65001 >nul
REM === WhatsApp bridge for سدن الصروح (business number 0570391199) ===
cd /d "%~dp0..\..\whatsapp-bridge"

REM Send ONLY to the owner (alerts) + customers who messaged us in the last 14 days
set WHATSAPP_SEND_ALLOWLIST=966597532622
set WHATSAPP_REPLY_WINDOW_HOURS=336
set WHATSAPP_SEND_RATE_LIMIT=20
set WHATSAPP_OUTBOUND_AUDIT=true

REM Forward incoming messages to the local agent only
set WEBHOOK_ENABLED=true
set WEBHOOK_URL=http://127.0.0.1:8769/whatsapp/webhook
set FORWARD_SELF=true
set WHATSAPP_AUTO_DOWNLOAD_MEDIA=false
set WHATSAPP_DEVICE_NAME=Sadan Agent

if exist whatsapp-bridge.exe (
  whatsapp-bridge.exe
) else (
  go run .
)
pause
