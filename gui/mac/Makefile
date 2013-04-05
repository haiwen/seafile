
top_dir=../..
all:

#all:app pack

app:
	make -C seafile

pack:
	cp -f ${top_dir}/net/daemon/ccnet seafile/
	cp -f ${top_dir}/seafile/daemon/.libs/seaf-daemon seafile/
	cp -f /opt/local/lib/libglib-2.0.0.dylib seafile/
	cp -f /opt/local/lib/libgobject-2.0.0.dylib seafile/
	cp -f /opt/local/lib/libssl.1.0.0.dylib seafile/
	cp -f /opt/local/lib/libcrypto.1.0.0.dylib seafile/
	cp -f /opt/local/lib/libevent-2.0.5.dylib seafile/
	cp -f /usr/local/lib/libsearpc.1.dylib seafile/
	cp -f ${top_dir}/lib/.libs/libccnet.0.dylib seafile/
	cp -f ${top_dir}/seafile/lib/.libs/libseafile.0.dylib seafile/

ccnetweb:
	rm -rf seafile/ccnetweb.app
	cp -rf ${top_dir}/web/dist/ccnetweb.app seafile/ccnetweb.app


uninstall:
install:
clean:
distclean:
distdir:
dist:
