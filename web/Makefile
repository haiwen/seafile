
all: i18n/zh_CN/LC_MESSAGES/messages.mo i18n/en_US/LC_MESSAGES/messages.mo


i18n/en_US/LC_MESSAGES/messages.mo: i18n/en_US/LC_MESSAGES/messages.po
	msgfmt -o i18n/en_US/LC_MESSAGES/messages.mo i18n/en_US/LC_MESSAGES/messages.po

i18n/zh_CN/LC_MESSAGES/messages.mo: i18n/zh_CN/LC_MESSAGES/messages.po
	msgfmt -o i18n/zh_CN/LC_MESSAGES/messages.mo i18n/zh_CN/LC_MESSAGES/messages.po

clean:
	-rm -f i18n/zh_CN/LC_MESSAGES/messages.mo i18n/en_US/LC_MESSAGES/messages.mo

check:

distclean: clean

install:

uninstall:

tags:
