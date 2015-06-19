@echo off
cd /d %~dp0
set PYTHONPATH=%PYTHONPATH%;%~dp0\..\seahub\thirdpart
start python py/upgrade_4.1_4.2.py
