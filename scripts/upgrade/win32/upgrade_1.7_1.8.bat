@echo off
cd /d %~dp0
set PYTHONPATH=%PYTHONPATH%;%~dp0\..\seahub\thirdpart
start python py/upgrade_1.7_1.8.py
