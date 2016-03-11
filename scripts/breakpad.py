#!/usr/bin/env python
#coding: UTF-8
"""Generate the breakpad symbol file and place it in the directory structure
required by breakpad `minidump_stackwalk` tool.

The directory is ./symbols/seaf-daemon.exe/${symbol_id}/seaf-daemon.exe.sym,
where symbol_id is the first line of the "dump_syms" output.
"""

from __future__ import print_function
import os
from os.path import abspath, basename, exists, dirname, join
import re
import sys
import subprocess
import optparse


def call(*a, **kw):
    kw.setdefault('shell', True)
    subprocess.check_call(*a, **kw)


def get_command_output(cmd, **kw):
    shell = not isinstance(cmd, list)
    return subprocess.check_output(cmd, shell=shell, **kw)


def main():
    parser = optparse.OptionParser()
    parser.add_option('--output', help='the path of the symbol file.')
    args, _ = parser.parse_args()

    seafile_src_dir = dirname(abspath(dirname(__file__)))
    os.chdir(seafile_src_dir)
    program = 'seaf-daemon.exe' if os.name == 'nt' else 'seaf-daemon'
    seaf_daemon = join('daemon', '.libs', program)
    if not exists(seaf_daemon):
        seaf_daemon = join('daemon', program)
        if not exists(seaf_daemon):
            raise RuntimeError('seaf-daemon executable not found!')
    symbols = get_command_output('dump_syms {}'.format(seaf_daemon))

    if args.output:
        symbol_file = args.output
    else:
        symbol_id = symbols.splitlines()[0].split()[3]
        symbol_dir = join('symbols', program, symbol_id)
        if not exists(symbol_dir):
            os.makedirs(symbol_dir)
        symbol_file = join(symbol_dir, '{}.sym'.format(program))
    print('symbols written to {}'.format(symbol_file))
    with open(symbol_file, 'w') as fp:
        fp.write(symbols)


if __name__ == '__main__':
    main()
