#coding: utf-8

import os
import ConfigParser

class Setting():
    def __init__(self):
        self.server_url = None
        self.user = None
        self.password = None

    def parse_config(self):
        config_path = None
        if os.environ.has_key('TEST_CONFIFG'):
            config_path = os.environ['TEST_CONFIG']
        else:
            config_path = os.path.join(os.getcwd(), 'test.conf')

        if not os.path.exists(config_path):
            raise Exception("Test config %s doesn't exist" % config_path)

        parser = ConfigParser.ConfigParser()
        parser.read(config_path)
        self.server_url = parser.get('test', 'server_url')
        self.user = parser.get('test', 'user')
        self.password = parser.get('test', 'password')
