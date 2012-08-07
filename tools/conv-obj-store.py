#!/usr/bin/env python

import os
import sys

obj_dir = sys.argv[1]

obj_list = os.listdir(obj_dir)
for obj_id in obj_list:
    old_path = os.path.join(obj_dir, obj_id)
    l1_dir = os.path.join(obj_dir, obj_id[:2])
    if not os.access(l1_dir, os.F_OK):
        try:
            os.mkdir(l1_dir)
        except:
            pass
    new_path = os.path.join(l1_dir, obj_id[2:])
    try:
        os.rename(old_path, new_path)
    except:
        pass
