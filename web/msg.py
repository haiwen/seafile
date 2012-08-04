
from seaserv import get_user_messages, get_group_messages, get_messages, \
    count_message, count_user_message, count_group_message


class reply:

    def GET(self):
        inputs = web.webapi.input(msgid='')
        msg_id = inputs.msgid
        if not msg_id:
            return web.seeother('msgs')
        msg = seamsg_rpc.get_message_by_id(msg_id)
        if not msg:
            return web.seeother('msgs')
        children = seamsg_rpc.get_message_children(msg_id)
        return render.reply(msg=msg, children=children, **default_options)

    def POST(self):
        inputs = web.webapi.input(content='', msgid='')
        content = inputs.content
        msgid = inputs.msgid
        if not content:
            referer = web.ctx.env.get('HTTP_REFERER', '/reply/?msgid='+msgid)
            raise web.seeother(referer)
        msg = seamsg_rpc.get_message_by_id(msgid)
        if not msg:
            return render.error(errmsg="No such message", **default_options)

        if msg.props.is_to_group:
            seamsg_rpc.send_message_group(msg.props.dest,
                                          content.encode('utf-8'), msgid)
        else:
            seamsg_rpc.send_message_user(msg.props.src,
                                         content.encode('utf-8'), msgid)
        referer = web.ctx.env.get('HTTP_REFERER', '/reply/?msgid='+msgid)
        raise web.seeother(referer)


class msgs:

    def common_options(self):
        inputs = web.webapi.input(dtype='', dest='', page=1)
        options = dict(default_options)
        offset = (int(inputs.page) - 1)*10
        if inputs.dtype == "group":
            msgs = get_group_messages(inputs.dest, offset, 10)
            count = count_group_message(inputs.dest)
        elif inputs.dtype == "user":
            msgs = get_user_messages(inputs.dest, offset, 10)
            count = count_user_message(inputs.dest)
        else:
            msgs = get_messages(offset, 10)
            count = count_message()

        groups = get_groups()
        users = get_users()
        options['messages'] = msgs
        options['count'] = count
        options['users'] = users
        options['peers'] = peers
        options['groups'] = groups
        options['dtype'] = inputs.dtype
        options['dest'] = inputs.dest
        return options

    def GET(self):
        options = self.common_options()
        return render.msgs(**options)

    def POST(self):
        inputs = web.webapi.input(content='', dtype='', dest='')
        content = inputs.content
        dtype = inputs.dtype
        dest = inputs.dest
            
        if content and dtype and dest:
            if dtype == 'user':
                seamsg_rpc.send_message_user(dest, content.encode('utf-8'), "")
            elif dtype == 'group':
                seamsg_rpc.send_message_group(dest, content.encode('utf-8'), "")
        referer = web.ctx.env.get('HTTP_REFERER', '/msgs/')
        raise web.seeother(referer)


class status:
    def GET(self):
        inputs = web.webapi.input(uuid='')
        status = {}
        status_str = None
        msg = None
        
        if inputs.uuid:
            uuid = inputs.uuid
            status_str = seamsg_rpc.get_message_rtimes(uuid)
            msg = seamsg_rpc.get_message_by_id(uuid)
        if status_str:
            members = status_str.split('\n')
            for member in members:
                pair = member.split(' ')
                if len(pair) == 2 :
                    status[pair[0]] = int(pair[1])
        
        return render.status(status=status, msg=msg, **default_options)
