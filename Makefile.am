if COMPILE_CLIENT
  MAKE_CLIENT = daemon gui
  MAKE_data = data # Caution: don't use MAKE_DATA
  MAKE_PO = po
endif

if COMPILE_HTTPSERVER
  MAKE_HTTPSERVER = httpserver
endif

if COMPILE_SERVER
  MAKE_SERVER = server tools monitor $(MAKE_HTTPSERVER) controller
endif

if WIN32
  MAKE_data =
endif

SUBDIRS = include lib common app python tests doc \
	$(MAKE_CLIENT) $(MAKE_SERVER) $(MAKE_PO) $(MAKE_data)

DIST_SUBDIRS = include lib common app python tests \
	daemon gui server tools monitor httpserver controller \
	po data doc

INTLTOOL = \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in

EXTRA_DIST = install-sh $(INTLTOOL) README.markdown web scripts debian msi LICENCE.txt

DISTCLEANFILES = \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in

DISTCHECK_CONFIGURE_FLAGS = --enable-server --enable-httpserver

ACLOCAL_AMFLAGS = -I m4

web_mos = \
	web/i18n/en_US/LC_MESSAGES/messages.mo \
	web/i18n/zh_CN/LC_MESSAGES/messages.mo

CLEANFILES = $(web_mos)

web/i18n/en_US/LC_MESSAGES/messages.mo: $(top_srcdir)/web/i18n/en_US/LC_MESSAGES/messages.po
	mkdir -p `dirname $@`
	msgfmt -o $@ $<

web/i18n/zh_CN/LC_MESSAGES/messages.mo: $(top_srcdir)/web/i18n/zh_CN/LC_MESSAGES/messages.po
	mkdir -p `dirname $@`
	msgfmt -o $@ $<

install-web:
	$(INSTALL) -d $(DESTDIR)$(pkgdatadir)
	if test -d $(DESTDIR)$(pkgdatadir)/web; then \
		rm -rf $(DESTDIR)$(pkgdatadir)/web; \
	fi
	cp -r $(top_srcdir)/web $(DESTDIR)$(pkgdatadir)

uninstall-web:
	chmod u+rw -R $(DESTDIR)$(pkgdatadir)/web
	-rm -rf $(DESTDIR)$(pkgdatadir)/web

if COMPILE_CLIENT
bin_SCRIPTS = seafile-web
install_web = install-web
uninstall_web = uninstall-web
make_web_mos = $(web_mos)
endif

all-local: $(make_web_mos)
install-data-local: $(install_web)
uninstall-local: $(uninstall_web)

