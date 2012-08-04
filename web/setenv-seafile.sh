CCNET_DIR=`pwd`/..

if [ $1 = "1" ]; then
    export CCNET_CONF_DIR=$CCNET_DIR/seafile/tests/basic/conf1
elif [ $1 = "3" ]; then
    export CCNET_CONF_DIR=$CCNET_DIR/seafile/tests/basic/conf3
fi

echo "CCNET_CONF_DIR set to $CCNET_CONF_DIR"
export PYTHONPATH=/opt/lib/python2.6/site-packages
