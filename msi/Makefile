CULTURE = zh-cn
LANG_FILE = zh_CN.wxl
TARGET = seafile.msi
ifeq (${MAKECMDGOALS}, en)
	CULTURE = en-us
	LANG_FILE = en_US.wxl
	TARGET = seafile-en.msi
endif

all : $(TARGET)
en: all

CC=candle.exe
LD=light.exe

CFLAGS = -nologo -ext WixUIExtension -ext WixUtilExtension
LDFLAGS = -nologo -spdb -ext \
	WixUIExtension -ext WixUtilExtension \
	-loc ${LANG_FILE} -cultures:${CULTURE}

sources = WixUI_InstallDir_NoLicense.wxs MyInstallDirDlg.wxs \
	seafile.wxs fragment.wxs 

OBJECTS = ${sources:%.wxs=%.wixobj} 

fragment.wxs: 
	Paraffin.exe -dir bin -g -alias bin -custom bin fragment.wxs

%.wixobj : %.wxs
	$(CC) $(CFLAGS) $< -o $@

seafile.wixobj : seafile.wxs Includes.wxi
	$(CC) $(CFLAGS) $< -o $@

$(TARGET) : $(OBJECTS) $(LANG_FILE)
	$(LD) $(LDFLAGS) $(OBJECTS) -o $@

clean :
	rm -f $(OBJECTS) *.msi fragment.*

.PHONY: all en clean
