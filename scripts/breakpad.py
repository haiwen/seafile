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


def generate_seafile_breakpad_symbol(project_dir, program_name, symbols_output):
    """
    :param project_dir : [string]
    :param program_name : [string]
    :param symbols_output: [string]
    :return: None

    generate_seafile_breakpad_symbol
    """
    os.chdir(project_dir)
    seaf_daemon = join('daemon', '.libs', program_name)
    if not exists(seaf_daemon):
        seaf_daemon = join('daemon', program_name)
        if not exists(seaf_daemon):
            raise RuntimeError('seaf-daemon executable not found!')
    symbols = get_command_output('dump_syms {}'.format(seaf_daemon))

    if symbols_output:
        symbol_file = symbols_output
    else:
        symbol_id = symbols.splitlines()[0].split()[3]
        symbol_dir = join('symbols', program_name, symbol_id)
        if not exists(symbol_dir):
            os.makedirs(symbol_dir)
        symbol_file = join(symbol_dir, '{}.sym'.format(program_name))
    print('symbols written to {}'.format(symbol_file))
    with open(symbol_file, 'w') as fp:
        fp.write(symbols)


def generate_seafile_gui_breakpad_symbol(project_dir, program_name, symbol_output):
    """
    :param project_dir: [string]
    :param program_name: [string]
    :param symbol_output: [string]
    :return: None

     generate seafile gui breakpad symbol
     """

    os.chdir(project_dir)
    seafile_gui_path = os.path.join(project_dir, program_name)
    if not exists(seafile_gui_path):
        raise RuntimeError('seafile gui executable not found !')

    symbols = get_command_output('dump_syms {}'.format(seafile_gui_path))

    with open(symbol_output, 'w') as fp:
        fp.write(symbols)


def main():
    parser = optparse.OptionParser()
    parser.add_option('--projectSrc', help='the project source file directory')
    parser.add_option('--name', help='the program name need to generated breakpad symbol')
    parser.add_option('--output', help='the path of the symbol file.')
    args, _ = parser.parse_args()

    src_dir = args.projectSrc
    program_name = args.name
    symbols_output = args.output
    if program_name == 'seaf-daemon.exe' or program_name == 'seaf-daemon':
        # generate seafile breakpad symbols
        generate_seafile_breakpad_symbol(src_dir, program_name, symbols_output)
    else:
        # generate seafile-gui breakpad symbols
        generate_seafile_gui_breakpad_symbol(src_dir, program_name, symbols_output)


if __name__ == '__main__':
    main()
