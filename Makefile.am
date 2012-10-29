
if COMPILE_GUI
  MAKE_GUI = gui
  MAKE_PO = po
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

if WIN32
  SHELL_EXT = desktop desktop/explorer
else
  SHELL_EXT = desktop desktop/nautilus
endif

SUBDIRS = include data lib common daemon $(MAKE_GUI) $(MAKE_CLINET) $(MAKE_SERVER) \
	app python tests web $(MAKE_PO)
DIST_SUBDIRS = include data lib common daemon gui daemon server tools monitor \
			   httpserver controller app python tests web

INTLTOOL = \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in

EXTRA_DIST = install-sh $(INTLTOOL) web debian/seafile.desktop README.markdown

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
	$(INSTALL) -d $(DESTDIR)$(datarootdir)/applications
	$(INSTALL_PROGRAM) debian/seafile.desktop $(DESTDIR)$(datarootdir)/applications/seafile.desktop
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
	-rm -rf $(DESTDIR)${pkglibdir}/web
	-rm -rf $(DESTDIR)${bindir}/ccnet-web.sh
	-rm -rf $(DESTDIR)${datarootdir}/applications

distcheck-hook:
	chmod u+rwx -R $(distdir)
	mkdir -p $(distdir)/_build/lib/
	cp -r $(distdir)/debian $(distdir)/_build/
	cp -r $(distdir)/web $(distdir)/_build/

distcleancheck:
	-rm $(distdir)/_build/debian
	-rm $(distdir)/_build/web
