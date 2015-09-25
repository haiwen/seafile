## Prerequisite

pip install -r requirements.txt

## Run

1. cp run.sh.template run.sh && cp test.conf.template test.conf
2. modify PYTHONPATH, PATH in run.sh
    * note you must copy seafile related site_packages to test machine and point the path in PYTHONPATH
    * note you must point seaf-daemon, ccnet file path in PATH
3. modify server_url, user, password in test.conf
4. start seahub server
5. execute ./run.sh test
