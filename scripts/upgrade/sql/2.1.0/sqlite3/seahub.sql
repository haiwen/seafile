CREATE TABLE IF NOT EXISTS "captcha_captchastore" (
    "id" integer NOT NULL PRIMARY KEY,
    "challenge" varchar(32) NOT NULL,
    "response" varchar(32) NOT NULL,
    "hashkey" varchar(40) NOT NULL UNIQUE,
    "expiration" datetime NOT NULL
);

DROP TABLE IF EXISTS "notifications_usernotification";
CREATE TABLE IF NOT EXISTS "notifications_usernotification" (
    "id" integer NOT NULL PRIMARY KEY,
    "to_user" varchar(255) NOT NULL,
    "msg_type" varchar(30) NOT NULL,
    "detail" text NOT NULL,
    "timestamp" datetime NOT NULL,
    "seen" bool NOT NULL
);

CREATE INDEX IF NOT EXISTS "notifications_usernotification_265e5521" ON "notifications_usernotification" ("msg_type");
CREATE INDEX IF NOT EXISTS "notifications_usernotification_bc172800" ON "notifications_usernotification" ("to_user");

CREATE TABLE IF NOT EXISTS "options_useroptions" (
    "id" integer NOT NULL PRIMARY KEY,
    "email" varchar(255) NOT NULL,
    "option_key" varchar(50) NOT NULL,
    "option_val" varchar(50) NOT NULL
);
CREATE INDEX IF NOT EXISTS "options_useroptions_830a6ccb" ON "options_useroptions" ("email");

CREATE TABLE IF NOT EXISTS "profile_detailedprofile" (
    "id" integer NOT NULL PRIMARY KEY,
    "user" varchar(255) NOT NULL,
    "department" varchar(512) NOT NULL,
    "telephone" varchar(100) NOT NULL
);
CREATE INDEX IF NOT EXISTS "profile_detailedprofile_6340c63c" ON "profile_detailedprofile" ("user");

CREATE TABLE IF NOT EXISTS "share_uploadlinkshare" (
    "id" integer NOT NULL PRIMARY KEY,
    "username" varchar(255) NOT NULL,
    "repo_id" varchar(36) NOT NULL,
    "path" text NOT NULL,
    "token" varchar(10) NOT NULL UNIQUE,
    "ctime" datetime NOT NULL,
    "view_cnt" integer NOT NULL
);
CREATE INDEX IF NOT EXISTS "share_uploadlinkshare_2059abe4" ON "share_uploadlinkshare" ("repo_id");
CREATE INDEX IF NOT EXISTS "share_uploadlinkshare_ee0cafa2" ON "share_uploadlinkshare" ("username");
