# used to generate update po files when new HTML templates is added


# generate new po file
echo [gettext] generate new po file
python ./pygettext.py -a -v -d messages -o i18n/messages.new.po main.py templates/*.html

# merge with old po file
# msgcat -o i18n/messages.en_us.po --use-first i18n/en_US/LC_MESSAGES/messages.po i18n/messages.new.po
echo [msgmerge] merge po files
msgmerge -o i18n/messages.merged.po i18n/zh_CN/LC_MESSAGES/messages.po i18n/messages.new.po

# overwrite old po files
# cp i18n/messages.en_us.po i18n/en_US/LC_MESSAGES/messages.po
echo [OK] overwrite old po file
cp i18n/messages.merged.po i18n/zh_CN/LC_MESSAGES/messages.po

# clean
echo [DONE] CLEANUP
rm i18n/messages.*.po

