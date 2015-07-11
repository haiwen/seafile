#!/bin/bash

SCRIPT=$(readlink -f "$0")
UPGRADEDIR=$(dirname "${SCRIPT}")
INSTALLPATH=$(dirname "${UPGRADEDIR}")
TOPDIR=$(dirname "${INSTALLPATH}")

seahub_secret_keygen=${INSTALLPATH}/seahub/tools/secret_key_generator.py
seahub_settings_py=${TOPDIR}/seahub_settings.py

line="SECRET_KEY = \"$(python $seahub_secret_keygen)\""

sed -i -e "/SECRET_KEY/c\\$line" $seahub_settings_py
