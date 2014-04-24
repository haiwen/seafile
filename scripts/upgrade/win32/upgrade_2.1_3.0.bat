@echo off
cd /d %~dp0
set PYTHONPATH=%PYTHONPATH%;%~dp0\..\seahub\thirdpart
start python py/upgrade_2.1_3.0.py
