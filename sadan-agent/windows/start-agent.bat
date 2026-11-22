@echo off
chcp 65001 >nul
REM === سدن الصروح auto-reply agent (needs Ollama running) ===
cd /d "%~dp0.."
if not exist config.json copy config.example.json config.json >nul
python agent.py
pause
