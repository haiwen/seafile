SUBDIRS = include lib common daemon app doc

DIST_SUBDIRS = include lib common app daemon doc

EXTRA_DIST = install-sh $(INTLTOOL) README.markdown scripts debian msi LICENSE.txt

ACLOCAL_AMFLAGS = -I m4

dist-hook:
	git log --format='%H' -1 > $(distdir)/latest_commit
