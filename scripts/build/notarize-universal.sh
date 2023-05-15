#!/bin/bash

set -e
set -x

pkg=${1?:"You must provide the path to the dmg file"}
if [[ ! -e $pkg ]]; then
    echo "File $pkg does not exist"
    exit 1
fi

security -v unlock-keychain -p vagrant || true
sudo security -v unlock-keychain -p vagrant || true

NOTARIZE_APPLE_ID="${NOTARIZE_APPLE_ID}"
NOTARIZE_PASSWORD="${NOTARIZE_PASSWORD}"
NOTARIZE_TEAM_ID="${NOTARIZE_TEAM_ID}"

BUNDLE_ID="com.seafile.seafile-client"

cd /tmp/

echo "Uploading $pkg for notarizing ..."

OPTS="--apple-id $NOTARIZE_APPLE_ID --password $NOTARIZE_PASSWORD --team-id $NOTARIZE_TEAM_ID"

xcrun notarytool submit $pkg --wait $OPTS --verbose --output-format json > notarize.json
if ! grep -q '"status":"Accepted"' notarize.json; then
    echo "Notarization failed"
    exit 1
fi

echo "Notarization success, now stapling the installer ..."

xcrun stapler staple $pkg

echo "Notarization & stapling done."
