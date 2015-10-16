#!/bin/bash

set -e -x

pip install PIL --allow-all-external --allow-unverified PIL
pip install -r ./integration-tests/requirements.txt

pushd $HOME

# download precompiled libevhtp
libevhtp_bin=libevhtp-bin_1.2.0.tar.gz
wget https://dl.bintray.com/lins05/generic/libevhtp-bin/$libevhtp_bin
tar xf $libevhtp_bin
find $HOME/opt

# download precompiled libzdb
# zdb_bin=libzdb-bin_2.11.1.tar.gz
# wget https://dl.bintray.com/lins05/generic/libzdb-bin/$zdb_bin
# tar xf $zdb_bin
# sed -i -e "s|prefix=/opt/local|prefix=$HOME/opt/local|g" $HOME/opt/local/lib/pkgconfig/zdb.pc
# find $HOME/opt
pushd /tmp/
git clone --depth=1 https://github.com/haiwen/libzdb.git
cd libzdb
./bootstrap
./configure --prefix=$HOME/opt/local
make -j2
make install
popd

# download seahub thirdpart python libs
WGET="wget --no-check-certificate"
downloads=$HOME/downloads
thirdpart=$HOME/thirdpart

mkdir -p $downloads && cd $downloads
urls=(
    http://pypi.python.org/packages/source/g/gunicorn/gunicorn-0.16.1.tar.gz
    http://pypi.python.org/packages/source/f/flup/flup-1.0.tar.gz
    https://pypi.python.org/packages/source/c/chardet/chardet-2.3.0.tar.gz
    https://labix.org/download/python-dateutil/python-dateutil-1.5.tar.gz
    https://pypi.python.org/packages/source/s/six/six-1.9.0.tar.gz
    https://pypi.python.org/packages/source/d/django-statici18n/django-statici18n-1.1.3.tar.gz
    https://pypi.python.org/packages/source/d/django_compressor/django_compressor-1.4.tar.gz
)
# The basename of the download url is different from the tarball name.
[[ -e Django-1.5.12.tar.gz ]] || $WGET https://www.djangoproject.com/download/1.5.12/tarball -O Django-1.5.12.tar.gz
[[ -e djblets-0.6.14.tar.gz ]] || $WGET https://github.com/djblets/djblets/tarball/release-0.6.14 -O djblets-0.6.14.tar.gz
for url in ${urls[*]}; do
    [[ -e $(basename $url) ]] || $WGET $url
done

mkdir -p $thirdpart && cd $thirdpart
save_pythonpath=$PYTHONPATH
export PYTHONPATH=.
for tarball in $downloads/*.gz; do
    module=$(basename $tarball \
        | python -c "import sys, re; fn = sys.stdin.read().strip(); print re.match('(.*)-[0-9.]+.tar.gz', fn).group(1)")
    grep -i -q $module easy-install.pth || easy_install -d . $tarball
done
export PYTHONPATH=$save_pythonpath

ls -lht $thirdpart

popd
