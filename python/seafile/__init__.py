
from rpcclient import SeafileRpcClient as RpcClient
from rpcclient import SeafileThreadedRpcClient as ThreadedRpcClient
from rpcclient import MonitorRpcClient as MonitorRpcClient
from rpcclient import SeafServerRpcClient as ServerRpcClient
from rpcclient import SeafServerThreadedRpcClient as ServerThreadedRpcClient

class TaskType(object):
    DOWNLOAD = 0
    UPLOAD = 1
