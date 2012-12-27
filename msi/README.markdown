How to build seafile Windows MSI installer
===========

* Download Wix toolset.

    http://wix.sourceforge.net/downloadv35.html

  And extract downloaded zip file to someplace, such as c:/wix. And add it to system PATH.
  
  Wix requires .NET Framework (3.5 SP1 or above) to be installed.

* Download Paraffin.exe:

    http://www.wintellect.com/CS/files/folders/7420/download.aspx

  And put Paraffin.exe to c:/wix
  
* Compile & install ccnet:

    cd ccnet; make && make install
    cd seafile; make && make install

* cd msi/custom; make

* ./dll2pyd.sh; ./setupwin.sh /c/pack

* strip files for reduce size:

    cd /c/pack; python strip-files.py

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
3) update seafile version in web/main.py

And go through the compiling process above.


English Version
=========

Just before you run `setupwin.sh` in the `seafile` directory:

    cd seafile/gui/win;
    make clean; make en;

    cp seafile-applet.exe /c/pack/bin
    cd /c/pack
    make en ==> seafile-en.msi
    
