#!/bin/sh

VERSION=1.3.5
top_dir=${PWD}

exts=" /usr/lib/libresolv.9.dylib /usr/lib/libSystem.B.dylib /usr/lib/system/libcache.dylib /usr/lib/system/libcommonCrypto.dylib /usr/lib/system/libcompiler_rt.dylib /usr/lib/system/libcopyfile.dylib /usr/lib/system/libdispatch.dylib /usr/lib/system/libdnsinfo.dylib /usr/lib/system/libdyld.dylib /usr/lib/system/libkeymgr.dylib /usr/lib/system/liblaunch.dylib /usr/lib/system/libmacho.dylib /usr/lib/system/libmathCommon.A.dylib /usr/lib/system/libquarantine.dylib /usr/lib/system/libremovefile.dylib /usr/lib/system/libsystem_blocks.dylib /usr/lib/system/libsystem_c.dylib /usr/lib/system/libsystem_dnssd.dylib /usr/lib/system/libsystem_info.dylib /usr/lib/system/libsystem_kernel.dylib /usr/lib/system/libsystem_network.dylib /usr/lib/system/libsystem_notify.dylib /usr/lib/system/libsystem_sandbox.dylib /usr/lib/system/libunc.dylib /usr/lib/system/libunwind.dylib /usr/lib/system/libxpc.dylib /usr/lib/libobjc.A.dylib"


dylibs_com="/usr/local/lib/libccnet.0.dylib /usr/local/lib/libseafile.0.dylib /usr/local/lib/libsearpc.1.dylib /usr/local/lib/libsearpc-json-glib.0.dylib /opt/local/lib/libcrypto.1.0.0.dylib /opt/local/lib/libuuid.16.dylib /opt/local/lib/libevent-2.0.5.dylib /opt/local/lib/libssl.1.0.0.dylib /opt/local/lib/libgio-2.0.0.dylib /opt/local/lib/libgmodule-2.0.0.dylib /opt/local/lib/libgobject-2.0.0.dylib /opt/local/lib/libgthread-2.0.0.dylib /opt/local/lib/libffi.6.dylib /opt/local/lib/libglib-2.0.0.dylib /opt/local/lib/libintl.8.dylib /opt/local/lib/libiconv.2.dylib /opt/local/lib/libsqlite3.0.dylib /opt/local/lib/libz.1.dylib"

dylibs_orig=$dylibs_com

all_orig=$dylibs_orig" /usr/local/bin/ccnet /usr/local/bin/seaf-daemon"

dylibs=$dylibs_com
all=$dylibs" /usr/local/bin/ccnet /usr/local/bin/seaf-daemon"

while [ $# -ge 1 ]; do
  case $1 in
    "web" )
      echo "============================================================="
      pushd web
      python setup_mac.py py2app
      popd

      pushd gui/mac/seafile
      rm -rf seafileweb.app
      cp -rf ${top_dir}/web/dist/seafileweb.app seafileweb.app
      popd
      ;;

    "dylib" )
      pushd gui/mac/seafile
      for var in $all_orig ; do
          cp -f $var ./
          base=$(basename "$var")
          chmod 0744 $base
      done

      for var in $all ; do
          dyexe=$(basename "$var")
          echo "Deal with "$dyexe
          for libpath in $dylibs ; do
              lib=$(basename $libpath)
              if [ "$lib" = "$dyexe" ] ; then
                  echo "install_name_tool -id @loader_path/../Resources/$lib $dyexe"
                  install_name_tool -id @loader_path/../Resources/$lib $dyexe
              else
                  echo "install_name_tool -change $libpath @loader_path/../Resources/$lib $dyexe"
                  install_name_tool -change $libpath @loader_path/../Resources/$lib $dyexe
              fi
          done
      done
      popd
      ;;

    "10.7" )
      echo "build seafile.app for Mac OS X 10.7"
      pushd gui/mac/seafile
      rm -rf build
      xcodebuild -target seafile-release
      rm -rf ${top_dir}/../seafile-${VERSION}/seafile.app
      cp -rf build/Release/seafile.app ${top_dir}/../seafile-${VERSION}/seafile.app
      popd
      ;;

    "10.6" )
      echo "build seafile.app for Mac OS X 10.6"
      pushd gui/mac/seafile
      rm -rf build
      xcodebuild -target seafile-10.6
      rm -rf ${top_dir}/../seafile-${VERSION}/seafile.app
      cp -rf build/Release/seafile.app ${top_dir}/../seafile-${VERSION}/seafile.app
      popd
      ;;
    esac
    shift
done
