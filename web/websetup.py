from distutils.core import setup
import shutil
import py2exe
import glob
import os
import sys

sys.argv.append("py2exe")

targetname="seafile-web"
targetfile=targetname+".py"
shutil.copy("main.py", targetfile)

try:
    shutil.rmtree("dist")
except Exception:
    pass

shutil.copytree("i18n", "dist/i18n")
shutil.copytree("static", "dist/static")
shutil.copytree("templates", "dist/templates")

packages=["mako.cache", "utils"]
ex_files=[]
option = {"py2exe":
              {"includes" :[targetname],
               "packages" : packages,
               "bundle_files" : 3}}

setup(name=targetname,
      options = option,
      windows=[{"script":targetfile}],
      data_files=ex_files)

os.remove(targetfile)
