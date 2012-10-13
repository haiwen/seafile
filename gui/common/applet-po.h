#ifndef APPLET_PO_H
#define APPLET_PO_H

#define S_WINDOW_NAME                   "seafile-applet"
#define S_WINDOW_TITLE                  "Seafile 初始化"
#define S_USERNAME_TOO_SHORT            "用户名太短"
#define S_USERNAME_TOO_LONG             "用户名太长"
#define S_USERNAME_INVALID              "用户名只能由字母、数字和 ‘-’ 、 ‘_’ 组成"
#define S_CHOOSE_EXISTEDDIR             "请选择配置文件所在的目录"
#define S_USERID_INVALID                "错误的用户id"
#define S_PASSWD_NULL                   "密码不能为空"
#define S_PASSWD_TOO_SHORT              "密码太短"
#define S_PASSWD_TOO_LONG               "密码太长"
#define S_PASSWD_INVALID                "密码不能包含空格"
#define S_PASSWD_DIFFERENT              "两次输入的密码不一致"
#define S_CHOOSE_PROFILE                "请选择一个配置文件"

#define S_UNKNOWN_ERR                   "未知错误"
#define S_WRONG_PASSWD                  "密码错误"
#define S_NAME_NULL                     "用户名不能为空"
#define S_PERMISSION_ERROR              "权限不够"
#define S_CREATE_CONF_FAILED            "创建配置文件错误"
#define S_CREATE_SEAFILE_CONF_FAILED    "创建配置文件错误"
#define S_SELECT_CONFDIR                "请选择一个目录用于放置配置目录"
#define S_DEFAULT_CONFDIR               "由于未选择目录，使用默认配置文件目录"
#define S_SELECT_SEAFILEDIR             "请选择一个磁盘用于放置Seafile元数据"
#define S_SEAFILE_STARTUP               "Seafile 已启动"
#define S_SEAFILE_CLICK_HINT            "点击图标即可打开管理页面"
#define S_LOGIN_FAILED                  "登录失败： "
#define S_CONN_SERVER_TIEMOUT           "连接服务器超时"
#define S_CONNECTING_TO_SERVER          "正在连接服务器"
#define S_VALIDATING_USER               "正在验证用户名/密码"
#define S_INVALID_USER                  "错误的用户名/密码"
#define S_ENSURE_QUIT_INIT              "Seafile 初始化仍未完成。确认要退出吗？"
#define S_LOGIN_SUCCESS                 "登录成功"
#define S_CREATING_CONF                 "正在生成配置文件，请稍候"
#define S_ENSURE_SKIP_LOGIN             "确认跳过登录？"

#define S_PASSWD_EMPTY            "密码不能为空"
#define S_PASSWD_TOO_SHORT        "密码太短"
#define S_PASSWD_TOO_LONG         "密码太长"
#define S_PASSWD_MISMATCH         "两次输入的密码不一致"

#define S_DESC_EMPTY              "描述不能为空"
#define S_DESC_TOO_SHORT          "描述太短"
#define S_DESC_TOO_LONG           "描述太长"
#define S_ENSURE_QUIT             "确认退出?"

#define S_CREATING_REPO           "正在创建资料库"
#define S_ERROR_NO_DAEMON         "Seafile 未启动"
#define S_CREATE_REPO_SUCCESS     "操作成功"
#define S_CREATE_REPO_FAILED      "操作失败"

#define S_INTERNAL_ERROR          "内部错误"
#define S_ENSURE_QUIT_CREATE      "确认取消？"

#define S_BASE_SIZE_TOO_LARGE \
    "原始目录 \"%s\" 过大(%d MB)，最大允许的原始目录大小为 %d MB.\n\n 是否继续创建？"

#define S_FAILED_TO_CALC_DIR_SIZE   "统计原始目录 [%s] 大小失败"

#define S_INIT_REPO_DLG_ALREADY_OPENED "请先关闭上一个创建 Seafile 资料库的对话框！"

#define S_REPO_CREATED "已变为资料库"
#define S_REPO_REMOVED "已解除同步"
#define S_REPO_SYNC_DONE "已同步"

#define S_SEAFILE_IN_TRANSFER "Seafile 正在传输数据" 

#define S_NO_RELAY "您目前没有设置任何服务器，请到 Seafile 管理页面添加"

#define S_BOLD_FONT "宋体"

#define S_AVAILABLE "空闲"
#define S_AVAILABLE_UNKNOWN "空闲空间大小未知"

#define S_INIT_NICKNAME "设置昵称"
#define S_INIT_DISK     "选择磁盘"
#define S_INIT_LOGIN    "登录服务器"

#define S_REPO_SYNC_ERROR "同步时出错"
#define S_REPO_DELETED_ON_RELAY "已经被解除同步。\n原因：该目录已经在服务器上被删除"
#define S_REPO_ACCESS_DENIED "同步出错。\n您没有权限访问该资料库"
#define S_REPO_QUOTA_FULL "同步出错。\n该资料库所有者的空间限额已用完"

#define S_UPLOADING "正在上传"
#define S_DOWNLOADING "正在下载"

#define S_SPEED "速度"

#define S_YOU_HAVE_NOT_LOGGED_IN "您尚未登录服务器"
#define S_NOT_ALLOWED_PATH "\"%s\" 是 Seafile 的工作目录，因此不能把 \"%s\" 变为资料库。\n你可以在该目录下创建一个子目录，再将这个子目录变为资料库"

#define S_SEAFILE_APPLET_ALREAD_RUNNING "Seafile 已经在运行中"

#define S_USER_MANUAL_FILENAME "Seafile使用帮助.txt"

#define S_FAILED_DISABLE_AUTO_SYNC "暂停同步失败"
#define S_FAILED_ENABLE_AUTO_SYNC "开启同步失败"

#define S_TIP_AUTO_SYNC_DISABLED "Seafile 同步已暂停"

#endif
