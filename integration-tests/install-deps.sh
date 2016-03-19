#!/bin/bash

set -e -x

pip install http://effbot.org/media/downloads/PIL-1.1.7.tar.gz
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

mkdir -p $downloads $thirdpart
cd $thirdpart
save_pythonpath=$PYTHONPATH
export PYTHONPATH=.
urls=(
    https://pypi.python.org/packages/source/p/pytz/pytz-2016.1.tar.gz
    https://www.djangoproject.com/m/releases/1.8/Django-1.8.10.tar.gz
    https://pypi.python.org/packages/source/d/django-statici18n/django-statici18n-1.1.3.tar.gz
    https://pypi.python.org/packages/source/d/djangorestframework/djangorestframework-3.3.2.tar.gz
    https://pypi.python.org/packages/source/d/django_compressor/django_compressor-1.4.tar.gz

    https://pypi.python.org/packages/source/j/jsonfield/jsonfield-1.0.3.tar.gz
    https://pypi.python.org/packages/source/d/django-post_office/django-post_office-2.0.6.tar.gz

    http://pypi.python.org/packages/source/g/gunicorn/gunicorn-19.4.5.tar.gz
    http://pypi.python.org/packages/source/f/flup/flup-1.0.2.tar.gz
    https://pypi.python.org/packages/source/c/chardet/chardet-2.3.0.tar.gz
    https://labix.org/download/python-dateutil/python-dateutil-1.5.tar.gz
    https://pypi.python.org/packages/source/s/six/six-1.9.0.tar.gz

    https://pypi.python.org/packages/source/d/django-picklefield/django-picklefield-0.3.2.tar.gz
    https://pypi.python.org/packages/source/d/django-constance/django-constance-1.0.1.tar.gz

    https://pypi.python.org/packages/source/j/jdcal/jdcal-1.2.tar.gz
    https://pypi.python.org/packages/source/e/et_xmlfile/et_xmlfile-1.0.1.tar.gz
    https://pypi.python.org/packages/source/o/openpyxl/openpyxl-2.3.0.tar.gz
)
for url in ${urls[*]}; do
    path="${downloads}/$(basename $url)"
    if [[ ! -e $path ]]; then
        $WGET -O $path $url
    fi
    easy_install -d . $path
done
export PYTHONPATH=$save_pythonpath

popd
