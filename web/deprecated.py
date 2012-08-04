

class PubReposFetch:

    def render_fetch_page(self, error_msg=''):
        inputs = web.webapi.input(repo_id='',
                                  token='',
                                  op='',
                                  peer_id='')
        peer = ccnet_rpc.get_peer(inputs.peer_id)
        if not peer or not inputs.op:
            raise web.seeother('/repos/fetch')

        seafpub_rpc = get_seafpub_rpc (peer.props.id)

        # get repos info
        all_repos = seafpub_rpc.get_repo_list(0, 100)
        repos = []
        op = inputs.op
        for repo in all_repos:
            if repo.props.size > 0 and repo.props.last_modify > 0:
                r = get_repo(repo.props.id)
                if r and r.props.worktree:
                    if op == 'sync':
                        repos.append(repo)
                else:
                    if op == 'fetch':
                        repos.append(repo)

        return render.pubrepo_fetch(error_msg=error_msg,
                                    repo_id=inputs.repo_id,
                                    token=inputs.token,
                                    op=inputs.op,
                                    peer=peer,
                                    lan_peer_id=peer.props.id,
                                    repos=repos,
                                    **default_options)

    def GET(self):
        return self.render_fetch_page()


    def POST(self):
        inputs = web.webapi.input(repo_id='', token='', peer_id='', op='')
        peer = ccnet_rpc.get_peer(inputs.peer_id)
        if not peer or not inputs.op:
            raise web.seeother('/repos/fetch')

        if not inputs.token:
            token = 'default'
        else:
            token = inputs.token

        # print "TOKEN is ",token
        repo_id = inputs.repo_id.strip()

        if len(repo_id) != 36:
            return self.render_fetch_page(error_msg=_("Invalid Repo ID"))

        op = inputs.op
        if op == 'fetch':
            seafile_rpc.fetch(repo_id, peer.props.id, 'fetch_head', 'master', token)
        else:
            seafile_rpc.synclan(repo_id, peer.props.id, token)
        raise web.seeother('/repos/tasks/')


class synclan:
    def GET(self):
        peer_ids = ccnet_rpc.list_peers()
        lnet_peers = []
        for peer_id in peer_ids.split("\n"):
            # for handling the ending '\n'
            if peer_id == '':
                continue

            peer = ccnet_rpc.get_peer(peer_id)
            if peer.props.in_local_network:
                lnet_peers.append(peer)

        return render.synclan(lnet_peers=lnet_peers,
                              **default_options)

                                          
class repo_checkout_status:
    def GET(self):
        repo_id = web.webapi.input(repo='').repo
        task = None
        if repo_id:
            task = seafile_rpc.get_checkout_task(repo_id)
        ttask = {}
        if task:
            ttask['total_files'] = task.props.total_files
            ttask['finished_files'] = task.props.finished_files
            repo = seafile_rpc.get_repo(repo_id)
            if not repo:
                return json.dumps({})
            ttask['worktree'] = os.path.join(task.props.worktree_parent, repo.props.name)
        return json.dumps(ttask)


class pubrepo_op_status:
    def GET(self):
        inputs = web.webapi.input(peer_id='', repo_id='', op='')
        result = {}
        peer = ccnet_rpc.get_peer(inputs.peer_id)
        if not peer or peer.props.net_state != NET_STATE_CONNECTED:
            result['error'] = 'disconnected'
            return json.dumps(result)
        
        if inputs.op == 'fetch':
            t = seafile_rpc.find_transfer_task(inputs.repo_id)
            fetch_task = {}
            fetch_task['fetch_done'] = True
            if t:
                fetch_task['fetch_done'] = False
                fetch_task['ttype'] = t.props.ttype
                fetch_task['state'] = t.props.state
                fetch_task['rt_state'] = t.props.rt_state
                fetch_task['block_done'] = t.props.block_done
                fetch_task['block_total'] = t.props.block_total
                fetch_task['rate'] = t.props.rate
                fetch_task['error_str'] = t.props.error_str
            return json.dumps(fetch_task)

        if inputs.op == 'sync':
            slist = seafile_rpc.get_sync_task_list()
            sync_task = {}
            sync_task['sync_done'] = True
            if slist:
                for task in slist:
                    if task.props.dest_id == inputs.peer_id and task.props.repo_id == inputs.repo_id:
                        sync_task['sync_done'] = False
                        sync_task['state'] = task.props.state
                        sync_task['error'] = task.props.error
            return json.dumps(sync_task)


class pubrepos:

    def show_repos(self, peer_id):

        peer = ccnet_rpc.get_peer(peer_id)
        if not peer or peer.props.net_state != NET_STATE_CONNECTED:
            error_msg = _('peer not connected')
            return render.pubrepos(error_msg=error_msg,
                                   repos=[],
                                   lan_peer_id=peer_id,
                                   **default_options)
            
        seafpub_rpc = get_seafpub_rpc(peer_id)

        # get repos info
        repos = seafpub_rpc.get_repo_list(0, 100)
        for repo in repos:
            repo.is_broken = False
            if repo.props.size < 0 or repo.props.last_modify < 0:
                repo.is_broken = True
                
            repo.exists = False
            repo.just_fetched = False
            repo.can_sync = False
            local_repo = get_repo(repo.props.id)
            if local_repo:
                repo.exists = True
                if not local_repo.props.worktree_invalid:
                    repo.can_sync = True
                elif not local_repo.props.head_branch:
                    repo.just_fetched = True
                    
        repos.sort(key=lambda x: x.props.last_modify, reverse=True)

        return render.pubrepos(error_msg=None,
                               repos=repos,
                               lan_peer_id=peer_id,
                               **default_options)

    def GET(self):
        inputs = web.webapi.input(peer='')
        return self.show_repos(inputs.peer)
        
    def POST(self):
        inputs = web.webapi.input(peer='', repo='', token='', op='')
        token = inputs.token
        if not token:
            token = 'default'
        if (inputs.op == 'fetch'):
            seafile_rpc.fetch(inputs.repo, inputs.peer, 'fetch_head', 'master', token)
        else:
            seafile_rpc.synclan(inputs.repo, inputs.peer, token)

        return True

def get_lan_peers():
    lnet_peers = []
    try:
        peer_ids = ccnet_rpc.list_peers()
        for peer_id in peer_ids.split("\n"):
            # for handling the ending '\n'
            if peer_id == '':
                continue

            peer = ccnet_rpc.get_peer(peer_id)
            if peer.props.in_local_network:
                lnet_peers.append(peer)
    except:                
        pass
    finally:
        return lnet_peers

class pubrepo_operation:

    def perform_operation_get(self, op, peer_id, repo_id):
        seafpub_rpc = get_seafpub_rpc (peer_id)

        repo = seafpub_rpc.get_repo(repo_id)
        if not repo:
            raise web.seeother('/pubrepos/?peer=%s' % peer_id)

        if op == 'diff':
            inputs = web.webapi.input(old='', new='')
            new_commit = seafpub_rpc.get_commit(inputs.new)
            if inputs.old != '':
                old_commit = seafpub_rpc.get_commit(inputs.old)
            else:
                old_commit = None
            (new, removed, renamed, modified, conflict) = get_peer_diff(seafpub_rpc, repo_id, inputs.old, inputs.new)
            return render.pubrepo_diff(repo=repo,
                                       lan_peer_id=peer_id,
                                       new=new, removed=removed,
                                       renamed=renamed, modified=modified,
                                       new_commit=new_commit, old_commit=old_commit,
                                       **default_options)
        elif op == 'dir':
            inputs = web.webapi.input(root_id='', commit_id='')
            dirs = list_peer_dir(seafpub_rpc, inputs.root_id)
            return render.pubrepo_dir(repo=repo,
                                      lan_peer_id=peer_id,
                                      dirs=dirs,
                                      commit_id=inputs.commit_id,
                                      **default_options)
        elif op == 'sync':
            inputs = web.webapi.input(root_id='', commit_id='', token='')
            seafile_rpc.synclan(repo_id, peer_id, inputs.token)
            raise web.seeother('/repos/tasks/')

        raise web.seeother('/pubrepo/?peer=%s&repo=%s' % peer_id, repo_id)


    def perform_operation_post(self, op, peer_id, repo_id):
        seafpub_rpc = get_seafpub_rpc (peer_id)

        repo = seafpub_rpc.get_repo(repo_id)
        if not repo:
            raise web.seeother('/pubrepos/')
        raise web.seeother('/pubrepo/?peer=%s&repo=%s' % peer_id, repo_id)

    def GET(self):
        inputs = web.webapi.input(op='', peer='', repo='')
        if inputs.op and inputs.repo and inputs.peer:
            return self.perform_operation_get(inputs.op, inputs.peer, inputs.repo)
        if inputs.peer:
            raise web.seeother('/pubrepos/?peer=%s' % inputs.peer)
        else:
            raise web.seeother('/repos/')

    def POST(self):
        inputs = web.webapi.input(op='', peer='', repo='')
        if inputs.op and inputs.repo and inputs.peer:
            return self.perform_operation_post(inputs.op, inputs.peer, inputs.repo)
        if inputs.peer:
            raise web.seeother('/pubrepos/?peer=%s' % inputs.peer)
        else:
            raise web.seeother('/repos/')


def render_peers_page(error_msg=""):
    rpeers = ccnet_rpc.list_resolving_peers()

    peer_ids = ccnet_rpc.list_peers()
    peers = []
    for peer_id in peer_ids.split("\n"):
        # for handling the ending '\n'
        if peer_id == '':
            continue
        
        peer = ccnet_rpc.get_peer(peer_id)
        peers.append(peer)

    relays = []
    repos = get_repos ()
    for peer in peers:
        if peer.props.role_list.find("MyRelay") != -1:
            relays.append(peer)
            peer.has_repo = False
            for repo in repos:
                if repo.relay_id == peer.props.id:
                    peer.has_repo = True
                    break

    default_relay = get_default_relay()
    
    login_relay_id = None
    logout_relay_id = None
    bind_query_id = None
    
    for relay in relays:
        if login_relay_id and logout_relay_id and bind_query_id:
            break
            
        if not login_relay_id:
            if relay.props.bind_status != 1 and relay.props.login_started:
                login_relay_id = relay.props.id
                continue
                
        if not logout_relay_id:
            if relay.props.bind_status == 1 and relay.props.logout_started:
                logout_relay_id = relay.props.id
                continue

        if not bind_query_id:
            if relay.net_state == NET_STATE_CONNECTED and relay.bind_status == 0:
                bind_query_id = relay.id

    return render.peers(error_msg=error_msg,
                        rpeers=rpeers,
                        peers=peers,
                        relays=relays,
                        login_relay_id=login_relay_id,
                        logout_relay_id=logout_relay_id,
                        bind_query_id=bind_query_id,
                        default_relay=default_relay,
                        **default_options)


        
class peer_connection_check:
    def GET(self):
        inputs = web.webapi.input(peer_id='')
        peer = ccnet_rpc.get_peer(inputs.peer_id)
        connection_check = {}
        connection_check['in_connection'] = peer.props.in_connection
        connection_check['net_state'] = peer.props.net_state
        return json.dumps(connection_check)


class peers:

    def GET(self):
        return render_peers_page()


class rpeers_check:

    def GET(self):
        rpeers = ccnet_rpc.list_resolving_peers()
        data = {}
        data['len'] = len(rpeers)

        return json.dumps(data)


class peer_operation:

    def GET(self):
        inputs = web.webapi.input(op='', peer_id='')
        if inputs.op == 'delpeer' and inputs.peer_id:
            if len(inputs.peer_id) == 40:
                try:
                    peer = ccnet_rpc.get_peer(inputs.peer_id)
                    # remove repos on this relay when relay is deleted
                    if peer.props.role_list.find("MyRelay") != -1:
                        remove_repos_on_relay(peer.id)
                    send_command("del-peer %s" % inputs.peer_id)
                except:
                    pass

        if inputs.op == 'set-default-relay' and inputs.peer_id:
            try:
                send_command("set-relay --default %s" % inputs.peer_id)
            except:
                pass

        if inputs.op == 'connect' and inputs.peer_id:
            try:
                send_command("connect %s" % inputs.peer_id)
            except:
                pass
            peer = ccnet_rpc.get_peer(inputs.peer_id)
            peer_connect = {}
            peer_connect['in_connection'] = peer.props.in_connection
            peer_connect['net_state'] = peer.props.net_state
            return json.dumps(peer_connect)

        if inputs.op == 'disconnect' and inputs.peer_id:
            try:
                send_command("disconnect %s" % inputs.peer_id)
            except:
                pass
            peer = ccnet_rpc.get_peer(inputs.peer_id)
            peer_disconnect = {}
            peer_disconnect['net_state'] = peer.props.net_state
            return json.dumps(peer_disconnect)

        if inputs.op == 'conn-cancel':
            peer_addr = web.webapi.input(addr='').addr
            peer_port = web.webapi.input(port='').port
            if peer_addr and peer_port:
                try:
                    send_command("conn-cancel %s %s" % (peer_addr, peer_port))
                except:
                    pass

        if inputs.op == 'logout-relay':
            ccnet_rpc.logout_relay(inputs.peer_id)

        raise web.seeother('/peers/')
    
    def POST(self):
        inputs = web.webapi.input(op='', user_id='', peer_id='')
        msg = ''
        error_msg = ''

        if inputs.op == "add-relay":
            relay_address = web.webapi.input(relay_address="").relay_address.strip()
            if ' ' in relay_address:
                return render_peers_page(
                    error_msg=_("invalid relay address: spaces are not allowed"))

            try:
                relay_port = int(web.webapi.input(relay_port="0").relay_port)
            except ValueError, e:
                return render_peers_page(
                    error_msg=_("invalid relay port: not a valid port number"))

            if not relay_address or not relay_port:
                return render_peers_page(
                    error_msg=_("relay_address can not be empty"))
            else:
                if web.webapi.input(set_default_relay='off').set_default_relay == 'off':
                    call_add_relay(relay_address, relay_port)
                else:
                    call_set_relay(relay_address, relay_port)
                raise web.seeother('/peers/')

        elif inputs.op == 'login-relay':
            email = web.webapi.input(email="").email
            passwd = web.webapi.input(passwd="").passwd
            if not email or not passwd:
                return render_peers_page(
                    error_msg=_("email and password can not be empty"))
            else:
                peerid = web.webapi.input(peerid="").peerid
                try:
                    ccnet_rpc.login_relay(peerid, email, passwd)
                except:
                    pass
            raise web.seeother('/peers/')


class relay_login_status:
    def GET(self):
        inputs = web.webapi.input(login_relay_id='', logout_relay_id='', bind_query_id='')
        login_relay_id = inputs.login_relay_id
        logout_relay_id = inputs.logout_relay_id
        bind_query_id = inputs.bind_query_id
        
        relay = None
        result = {'reload': False}
        
        if login_relay_id:
            relay = ccnet_rpc.get_peer(login_relay_id)
            if relay:
                if relay.props.bind_status == 1 or relay.props.login_error:
                    result['reload'] = True
                    return json.dumps(result)

        if logout_relay_id:
            relay = ccnet_rpc.get_peer(logout_relay_id)
            if relay:
                if relay.props.bind_status != 1 or not relay.props.logout_started:
                    result['reload'] = True
                    return json.dumps(result)

        if bind_query_id:
            relay = ccnet_rpc.get_peer(bind_query_id)
            if relay:
                if relay.net_state != NET_STATE_CONNECTED or relay.bind_status != 0:
                    result['reload'] = True
                    return json.dumps(result)

        return json.dumps(result)


def call_set_relay(address, port):
    command = "set-relay --default --addr %s:%s" % (address, port)
    send_command(command)

def call_add_relay(address, port):
    command = "set-relay --addr %s:%s" % (address, port)
    send_command(command)
