@echo off
title ScamShield AI - Backend Engine
echo Starting ScamShield AI Backend Server on http://127.0.0.1:8000...
cd /d "%~dp0"
backend\venv\Scripts\python.exe backend\main.py
pause
