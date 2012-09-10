#!/bin/bash

function usage () {
    echo 
    echo "Usage: pack-server.sh <version>"
    echo 
}

if [[ $# != 1 ]]; then
    usage;
    exit 1;
fi

version=$1

if [[ ! ${version} =~ [0-9]\.[0-9]\.[0-9] ]]; then
    echo 
    echo "\"${version}\" is not a invalid version number"
    echo "a valid version is like 0.9.3."
    echo
    exit 1;
fi

# server_dir=seafile-server-${version}

# if [[ ! -d ${server_dir} ]]; then
#     echo
#     echo "The directory \"${server_dir}\" does not exist"
#     echo
#     exit 1;
# fi

serverpath=seafile-server-${version}

mv seafile-server ${serverpath}

tar czvf seafile-server_${version}_x86-64.tar.gz ${serverpath} --exclude-vcs --exclude=${serverpath}/seafile/share* --exclude=${serverpath}/seafile/include*  --exclude=${serverpath}/runtime/*.log --exclude=${serverpath}/runtime/*.pid --exclude=${serverpath}/seahub/seahub.db --exclude=${serverpath}/seahub/avatar/testdata --exclude=${serverpath}/seafile/lib/*.la --exclude=${serverpath}/seafile/lib/*.a --exclude=${serverpath}/seafile/lib/pkgconfig* --exclude=${serverpath}/seafile/bin/ccnet-tool --exclude=${serverpath}/seafile/bin/ccnet-servtool --exclude=${serverpath}/seafile/bin/ccnet-web.sh --exclude=${serverpath}/seafile/bin/ccnet-tool --exclude=${serverpath}/seafile/bin/searpc-codegen.py

mv ${serverpath} seafile-server 
