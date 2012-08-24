How to build seafile Windows MSI installer
===========

* Download Wix toolset.

    http://wix.sourceforge.net/downloadv35.html

  And extract downloaded zip file to someplace, such as c:/wix. And add it to system PATH.

* Download Paraffin.exe:

    http://www.wintellect.com/CS/files/folders/7420/download.aspx

  And put Paraffin.exe to c:/wix
  
* Compile & install ccnet:

    cd ccnet; make && make install
    cd seafile; make && make install

* cd msi/custom; make; make x64;

* ./dll2pyd.sh; ./setupwin.sh /c/pack

* Compile msi using Wix:

    cd /c/pack; make fragment.wxs; <Edit fragment.wxs> ; make ;

* Now you have the package available in /c/pack/seafile.msi

Edit fragment.wxs
=======

Edit the line contains seafile-applet. Modify the Id attribute.

From:
    <File Id="file_bin_28 Checksum="yes" Source="bin\seafile-applet.exe" />
To:
    <File Id="seafileapplet.exe" Checksum="yes" Source="bin\seafile-applet.exe" />


Upgrade
=========

Every time a new version is released, you just need to edit Includes.wxi:
1) Generate a new <ProductGuid>
2) Update <CurrentSeafileVersion>

And go through the compiling process above.
