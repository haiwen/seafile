@echo off
cd /d %~dp0
set PYTHONPATH=%PYTHONPATH%;%~dp0\..\seahub\thirdpart
start python py/upgrade_5.0_5.1.py
