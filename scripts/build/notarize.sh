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

APPLE_ACCOUNT=$(security find-generic-password -s "notarize username" -w)
APPLE_PASSWORD=$(security find-generic-password -s "notarize password" -w)

BUNDLE_ID="com.seafile.seafile-client"
altool_exe="/Applications/Xcode.app/Contents/Applications/Application Loader.app/Contents/Frameworks/ITunesSoftwareService.framework/Support/altool"

_altool() {
    "${altool_exe}" "$@"
}

cd /tmp/

echo "Uploading $pkg for notarizing ..."

_altool --notarize-app -t osx -f $pkg \
       --primary-bundle-id ${BUNDLE_ID} \
       -u ${APPLE_ACCOUNT} -p ${APPLE_PASSWORD} \
       --output-format xml > UploadInfo.plist

REQUESTID=$(xmllint --xpath "/plist/dict[key='notarization-upload']/dict/key[.='RequestUUID']/following-sibling::string[1]/node()" UploadInfo.plist)
echo "file $pkg uploaded for notarization, waiting for apple ..."
echo ${REQUESTID}
sleep 60
x=1
while [[ $x -le 15 ]]; do
    _altool --notarization-info ${REQUESTID} -u ${APPLE_ACCOUNT}  -p ${APPLE_PASSWORD} --output-format xml > RequestedInfo.plist
    ANSWER=$(xmllint --xpath "/plist/dict[key='notarization-info']/dict/key[.='Status']/following-sibling::string[1]/node()" RequestedInfo.plist)
    if [[ "$ANSWER" == "in progress" ]]; then
        echo "notarization in progress"
        sleep 60
        x=$((x+1))
    elif [[ "$ANSWER" == "success" ]]; then
        echo "notarization success"
        break
    else
        echo "notarization failed"
        break
        exit 1
    fi
done
ANSWER=$(xmllint --xpath "/plist/dict[key='notarization-info']/dict/key[.='Status']/following-sibling::string[1]/node()" RequestedInfo.plist)
if [[ "$ANSWER" != "success" ]]; then
    echo "notarization failed"
    exit 1
fi

echo "Notarization success, now stapling the installer ..."

xcrun stapler staple $pkg

echo "Notarization & stapling done."
