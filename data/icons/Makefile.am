SUBDIRS = 16x16 22x22 24x24 32x32 48x48 128x128 scalable

install-data-hook: update-icon-cache
uninstall-hook: update-icon-cache
update-icon-cache:
	@-if test -z "$(DESTDIR)"; then \
		echo "Updating Gtk icon cache."; \
		gtk-update-icon-cache || true; \
	else \
		echo "*** Icon cache not updated.  After (un)install, run this:" \
		echo "***   gtk-update-icon-cache"; \
	fi
