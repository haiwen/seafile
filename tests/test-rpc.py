import ccnet
import seafile

pool = ccnet.ClientPool("basic/conf1")
seafile_rpc = seafile.RpcClient(pool)

repos = seafile_rpc.get_repo_list("", 100)
for repo in repos:
    print repo

