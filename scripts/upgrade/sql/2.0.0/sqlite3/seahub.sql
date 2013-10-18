CREATE TABLE IF NOT EXISTS "base_groupenabledmodule" (
    "id" integer NOT NULL PRIMARY KEY,
    "group_id" varchar(10) NOT NULL,
    "module_name" varchar(20) NOT NULL
);

CREATE TABLE IF NOT EXISTS "base_userenabledmodule" (
    "id" integer NOT NULL PRIMARY KEY,
    "username" varchar(255) NOT NULL,
    "module_name" varchar(20) NOT NULL
);

CREATE TABLE IF NOT EXISTS "base_userlastlogin" (
    "id" integer NOT NULL PRIMARY KEY,
    "username" varchar(255) NOT NULL,
    "last_login" datetime NOT NULL
);

CREATE INDEX IF NOT EXISTS "base_groupenabledmodule_dc00373b" ON "base_groupenabledmodule" ("group_id");
CREATE INDEX IF NOT EXISTS "base_userenabledmodule_ee0cafa2" ON "base_userenabledmodule" ("username");
