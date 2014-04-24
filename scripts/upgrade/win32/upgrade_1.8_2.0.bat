@echo off
cd /d %~dp0
set PYTHONPATH=%PYTHONPATH%;%~dp0\..\seahub\thirdpart
start python py/upgrade_1.8_2.0.py
