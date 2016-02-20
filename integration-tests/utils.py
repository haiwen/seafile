#coding: UTF-8

import os
from os.path import abspath, basename, exists, expanduser, join
import sys
import re
import logging
from contextlib import contextmanager
from subprocess import Popen, PIPE, CalledProcessError

import termcolor
import requests
from pexpect import spawn

logger = logging.getLogger(__file__)

def _color(s, color):
    return s if not os.isatty(sys.stdout.fileno()) \
        else termcolor.colored(str(s), color)


def green(s):
    return _color(s, 'green')


def red(s):
    return _color(s, 'red')


def debug(fmt, *a):
    logger.debug(green(fmt), *a)


def info(fmt, *a):
    logger.info(green(fmt), *a)


def warning(fmt, *a):
    logger.warn(red(fmt), *a)


def shell(cmd, inputdata=None, **kw):
    info('calling "%s" in %s', cmd, kw.get('cwd', os.getcwd()))
    kw['shell'] = not isinstance(cmd, list)
    kw['stdin'] = PIPE if inputdata else None
    p = Popen(cmd, **kw)
    if inputdata:
        p.communicate(inputdata)
    p.wait()
    if p.returncode:
        raise CalledProcessError(p.returncode, cmd)


@contextmanager
def cd(path):
    olddir = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(olddir)


def chdir(func):
    def wrapped(self, *w, **kw):
        with cd(self.projectdir):
            return func(self, *w, **kw)

    return wrapped

def setup_logging():
    kw = {
        'format': '[%(asctime)s][%(module)s]: %(message)s',
        'datefmt': '%m/%d/%Y %H:%M:%S',
        'level': logging.DEBUG,
        'stream': sys.stdout,
    }

    logging.basicConfig(**kw)
    logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(
        logging.WARNING)
