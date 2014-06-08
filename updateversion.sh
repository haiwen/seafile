#! /bin/sh

if [ $# != "2" ]; then
    echo "$0 <old_version> <new_version>"
    exit
fi

old_ver=$1
new_ver=$2

if test "$(uname)" = "Darwin"; then
    sed -i '' -e "s|$old_ver|$new_ver|" web/setup_mac.py
    sed -i '' -e "s|VERSION=$old_ver|VERSION=$new_ver|" setupmac.sh
    sed -i '' -e "s|<string>$old_ver</string>|<string>$new_ver</string>|" gui/mac/seafile/seafile/*.plist
else
    sed -i  "s|$old_ver|$new_ver|" web/setup_mac.py
    sed -i "s|VERSION=$old_ver|VERSION=$new_ver|" setupmac.sh
    sed -i "s|<string>$old_ver</string>|<string>$new_ver</string>|" gui/mac/seafile/seafile/*.plist

fi

