@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" vulnerable\app.py
) else (
  py vulnerable\app.py
)
pause
