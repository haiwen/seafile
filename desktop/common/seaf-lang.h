#ifndef SEAF_LANG_EN

/* --------------------------------------------
 * Chinese menu text
 * -------------------------------------------- */

#define MENU_STRING_START_SEAFILE "启动 Seafile"
#define MENU_HELPTEXT_START_SEAFILE "Seafile 尚未运行，点击以启动。"

#define MENU_STRING_REFRESH "刷新"
#define MENU_HELPTEXT_REFRESH "对同步目录进行了创建/删除/同步等操作之后，需要刷新 Seafile 缓存"

#define MENU_STRING_INIT_REPO "变为同步目录"
#define MENU_HELPTEXT_INIT_REPO "把当前目录变为一个同步目录"

#define MENU_STRING_OPEN_WEB "打开管理页面"
#define MENU_HELPTEXT_OPEN_WEB "在浏览器中打开当前同步目录的页面"

#ifdef WIN32
    #define MENU_STRING_AUTO  "打开自动同步"
    #define MENU_STRING_MANUAL "关闭自动同步"
#else
    #define MENU_STRING_AUTO  "打开自动同步"
    #define MENU_STRING_MANUAL "关闭自动同步"
#endif

#define MENU_HELPTEXT_AUTO "打开自动同步后，目录有更改时会自动被同步，无需用户自己动手"
#define MENU_HELPTEXT_MANUAL "关闭自动同步后，当前目录的更改由需要由用户自己点击同步按钮来同步"

/* --------------------------------------------
 * Chinese messages
 * -------------------------------------------- */

#define MSG_FAIL_TO_START_SEAFILE           "启动 Seafile 失败"
#define MSG_BROWSER_NOT_FOUND               "没有找到你的浏览器"
#define MSG_OPEN_URL_YOURSELF               "请尝试在浏览器中手工打开这个链接"
#define MSG_OPERATION_FAILED                "操作失败"

#define MSG_PASSWD_EMPTY            "密码不能为空"
#define MSG_PASSWD_TOO_SHORT        "密码太短"
#define MSG_PASSWD_TOO_LONG         "密码太长"
#define MSG_PASSWD_MISMATCH         "两次输入的密码不一致"

#define MSG_DESC_EMPTY              "描述不能为空"
#define MSG_DESC_TOO_SHORT          "描述太短"
#define MSG_DESC_TOO_LONG           "描述太长"
#define MSG_ENSURE_QUIT             "确认退出?"

#define MSG_CREATING_REPO           "正在创建同步目录"
#define MSG_ERROR_NO_DAEMON         "Seafile 未启动"
#define MSG_CREATE_REPO_SUCCESS     "操作成功"
#define MSG_CREATE_REPO_FAILED      "操作失败"

#define MSG_INTERNAL_ERROR          "内部错误"


#else

/* --------------------------------------------
 * English menu text
 * -------------------------------------------- */

#define MENU_STRING_START_SEAFILE "Start Seafile"
#define MENU_HELPTEXT_START_SEAFILE "Seafile is not running. Click to start it."

#define MENU_STRING_REFRESH "Refresh"
#define MENU_HELPTEXT_REFRESH "Refresh the cached data after operations such as create/delete/commit"

#define MENU_STRING_INIT_REPO "Init a repo here"
#define MENU_HELPTEXT_INIT_REPO "create a repository from current folder "

#define MENU_STRING_OPEN_WEB "View in browser"
#define MENU_HELPTEXT_OPEN_WEB "view the status of this repo in your web browser"

#ifdef WIN32
    #define MENU_STRING_AUTO "Auto commit"
    #define MENU_STRING_MANUAL "Manual mode"
#else
    #define MENU_STRING_AUTO "Switch to auto commit"
    #define MENU_STRING_MANUAL "Switch to manual mode"
#endif

#define MENU_HELPTEXT_AUTO "Changes of this repository is committed automatically"
#define MENU_HELPTEXT_MANUAL "Changes of this repository need to be committed by yourself"

/* --------------------------------------------
 * English messages
 * -------------------------------------------- */

#define MSG_FAIL_TO_START_SEAFILE "Failed to start Seafile"
#define MSG_BROWSER_NOT_FOUND "Can't find your web browser"
#define MSG_OPEN_URL_YOURSELF "Please open this url yourself"
#define MSG_OPERATION_FAILED "Operation failed"

#endif
