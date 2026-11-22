@echo off
chcp 65001 >nul
cd /d "%~dp0.."
python learn_style.py
pause
