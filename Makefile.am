
if COMPILE_GUI
  MAKE_GUI = gui
endif

if COMPILE_HTTPSERVER
  MAKE_HTTPSERVER = httpserver
endif

if COMPILE_SERVER
  MAKE_SERVER = server tools monitor $(MAKE_HTTPSERVER) controller
endif

if COMPILE_CLIENT
  MAKE_CLIENT = daemon
endif

SUBDIRS = include lib common daemon $(MAKE_CLINET) $(MAKE_SERVER) \
	app python tests

INTLTOOL = \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in

EXTRA_DIST = config.rpath install-sh $(INTLTOOL) web

DISTCLEANFILES = \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in

ACLOCAL_AMFLAGS = -I m4

if !SERVER_ONLY
install-web:
	$(INSTALL_PROGRAM) ccnet-web.sh $(DESTDIR)${bindir}/ccnet-web.sh
	if test -d $(DESTDIR)${pkglibdir}/web; then \
	    rm -rf $(DESTDIR)${pkglibdir}/web; \
    fi
	cp -r ${top_srcdir}/web $(DESTDIR)${pkglibdir}
endif

install-data-local:
#	$(INSTALL) -d $(DESTDIR)$(datarootdir)/applications
#	$(INSTALL_PROGRAM) debian/seafile.desktop $(DESTDIR)$(datarootdir)/applications/seafile.desktop
	$(INSTALL) -d $(DESTDIR)${bindir}
	$(INSTALL_PROGRAM) ccnet-web.sh $(DESTDIR)${bindir}
	$(INSTALL) -d $(DESTDIR)${pkglibdir}
if !SERVER_ONLY
	if test -d $(DESTDIR)${pkglibdir}/web; then \
	    rm -rf $(DESTDIR)${pkglibdir}/web; \
    fi
	cp -r ${top_srcdir}/web $(DESTDIR)${pkglibdir}
endif

uninstall-hook:
	chmod u+rw -R $(DESTDIR)${pkglibdir}/web
	rm -rf $(DESTDIR)${pkglibdir}/web
