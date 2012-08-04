import ccnet
from pysearpc import searpc_func, SearpcError


class AppletRpcClient(ccnet.RpcClientBase):

    def __init__(self, ccnet_client_pool, retry_num=1, *args, **kwargs):
        ccnet.RpcClientBase.__init__(self, ccnet_client_pool, "applet-rpcserver",
                               *args, **kwargs)

    @searpc_func("int", [])
    def applet_get_auto_start(self):
        pass

    get_auto_start = applet_get_auto_start
        
    @searpc_func("int", ["string"])
    def applet_set_auto_start(self):
        pass

    set_auto_start = applet_set_auto_start

    @searpc_func("int", ["string"])
    def applet_open_dir(self):
        pass

    open_dir = applet_open_dir

