
######## seamsg API #####

def get_message(msgid):
    return seamsg_rpc.get_message_by_id(msgid)


def get_user_messages(user, offset, limit):
    """Get messages sent to or received from `user`.

    For example:
    
        get_user_message('eb812fd276432eff33bcdde7506f896eb4769da0', 0, 10)

    fetches the lastest 10 messages from the given user.

    :param user: user ID.
    :param offset: offset of the first message.
    :param limit: only fetch `limit` messages.
    """
    return seamsg_rpc.get_user_messages(user, offset, limit)


def get_group_messages(group, offset, limit):
    """Get messages of `group`."""
    return seamsg_rpc.get_group_messages(group, offset, limit)


def get_messages(offset, limit):
    """Get messages start at `offset`."""
    return seamsg_rpc.get_messages(offset, limit)

def count_message():
    return seamsg_rpc.count_message()

def count_user_message(user):
    return seamsg_rpc.count_user_message(user)

def count_group_message(group):
    return seamsg_rpc.count_group_message(group)
