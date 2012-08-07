#!/bin/bash

. ../common-conf.sh 

testdir=${seafile_dir}/tests/basic

conf1=${testdir}/conf1
conf2=${testdir}/conf2
conf3=${testdir}/conf3
conf4=${testdir}/conf4

peer1=c882e263e9d02c63ca6b61c68508761cbc74c358
peer2=376cf9b6ef33a6839cf1fc096131893b5ecc673f
peer3=1e5b5e0f49010b94aa6c2995a6e7b7cba462d388
peer4=93ae3e01eea6667cbdd03c4afde413ccd9f1eb43

${ccnet_server} -c ${conf2} &
${ccnet} -c ${conf1} --no-multicast -D Peer,Requirement,Group,Syncher,Message,Connection,Other -f - &
${ccnet} -c ${conf3} --no-multicast &
${ccnet} -c ${conf4} --no-multicast &

sleep 5

# ${ccnet_tool} -c ${conf1} set-relay --default --addr 127.0.0.1:10002
# ${ccnet_tool} -c ${conf3} set-relay --default --addr 127.0.0.1:10002
# ${ccnet_tool} -c ${conf4} set-relay --default --addr 127.0.0.1:10002

# sleep 20
echo "+++ Added relay"

# ${ccnet_servtool} -c ${conf2} add-client ${peer1}
# ${ccnet_servtool} -c ${conf2} add-client ${peer3}
# ${ccnet_servtool} -c ${conf2} add-client ${peer4}

# sleep 30
echo "+++ Added client"

#sleep 60

#echo "+++ Add chunk servers"
#./seafserv-tool -c conf2 add-server server
#./seafserv-tool -c conf2 add-server server2

echo "+++ clean up"
pkill -2 ccnet
