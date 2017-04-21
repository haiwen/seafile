SUBDIRS = include lib common daemon app doc python

DIST_SUBDIRS = include lib common app daemon doc python

EXTRA_DIST = install-sh $(INTLTOOL) README.markdown scripts debian msi LICENSE.txt dmg

ACLOCAL_AMFLAGS = -I m4

dist-hook:
	git log --format='%H' -1 > $(distdir)/latest_commit
