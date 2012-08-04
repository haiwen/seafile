# encoding: utf-8
from datetime import datetime
import stat
import gettext
import re
from po import TRANSLATION_MAP

def translate_time_sec(time):
    return datetime.fromtimestamp(
        (float(time))).strftime("%Y-%m-%d %H:%M:%S")

def translate_time_usec(time):
    return datetime.fromtimestamp(
        (float(time))/1000000).strftime("%Y-%m-%d %H:%M:%S")

def format_file_size(size):
    if size < 1024:
        return "%dB" % size
    r = float(size)
    r = r / 1024
    if r < 1024:
        return "%.2fKB" % r
    
    r = r / 1024
    if r < 1024:
        return "%.2fMB" % r
    
    r = r / 1024
    return "%.2fGB" % r

def format_file_mode(mode):
    if stat.S_ISREG(int(mode)):
        return "f"
    else:
        return "d"

def format_creator(name):
    return name.partition('@')[0]


def translate_commit_desc(value):
    """Translate commit description."""
    if value.startswith('Reverted repo'):
        return value.replace('Reverted repo to status at', u'同步目录内容还原到')
    elif value.startswith('Reverted file'):
        value = value.replace('Reverted file', u'还原文件')
        value = value.replace('to status at', u'内容到')
        return value
    elif value.startswith('Merged'):
        return u'合并了其他人的修改'
    else:
        operations = '|'.join(TRANSLATION_MAP.keys())
        patt = r'(%s) "(.*)"\s?(and ([0-9]+) more files)?' % operations

        ret_list = []
        for e in value.split('\n'):
            if not e:
                continue

            m = re.match(patt, e)
            if not m:
                ret_list.append(e)
                continue
        
            op = m.group(1)
            op_trans = TRANSLATION_MAP.get(op)
            file_name = m.group(2)
            more_files = m.group(3)
            n_files = m.group(4)
    
            if not more_files:
                ret = op_trans + u' "' + file_name + u'".'
            else:
                ret = op_trans + u' "' + file_name + u'"以及另外' + n_files + u'个文件.'
            ret_list.append(ret)

        return '\n'.join(ret_list)

