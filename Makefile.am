MAKE_CLIENT =

if COMPILE_CLIENT
  MAKE_CLIENT += daemon
  MAKE_data = data # Caution: don't use MAKE_DATA
endif

if WIN32
  MAKE_data =
  MAKE_CONTROLLER =
else
  MAKE_CONTROLLER = controller
endif

if COMPILE_FUSE
  MAKE_FUSE = fuse
else
  MAKE_FUSE =
endif

if COMPILE_SERVER
  MAKE_SERVER = server tools httpserver $(MAKE_CONTROLLER) $(MAKE_FUSE)
endif

SUBDIRS = include lib common app python tests doc \
	$(MAKE_CLIENT) $(MAKE_SERVER) $(MAKE_data)

DIST_SUBDIRS = include lib common app python tests \
	daemon server tools httpserver controller \
	data doc fuse

INTLTOOL = \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in

EXTRA_DIST = install-sh $(INTLTOOL) README.markdown scripts debian msi LICENCE.txt

DISTCHECK_CONFIGURE_FLAGS = --enable-server

ACLOCAL_AMFLAGS = -I m4

dist-hook:
	git log --format='%H' -1 > $(distdir)/latest_commit
