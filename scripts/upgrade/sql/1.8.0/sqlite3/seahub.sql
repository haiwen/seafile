CREATE TABLE IF NOT EXISTS "share_privatefiledirshare" (
    "id" integer NOT NULL PRIMARY KEY,
    "from_user" varchar(255) NOT NULL,
    "to_user" varchar(255) NOT NULL,
    "repo_id" varchar(36) NOT NULL,
    "path" text NOT NULL,
    "token" varchar(10) NOT NULL UNIQUE,
    "permission" varchar(5) NOT NULL,
    "s_type" varchar(5) NOT NULL
);

CREATE TABLE IF NOT EXISTS "message_usermsgattachment" (
    "id" integer NOT NULL PRIMARY KEY,
    "user_msg_id" integer NOT NULL REFERENCES "message_usermessage" ("message_id"),
    "priv_file_dir_share_id" integer REFERENCES "share_privatefiledirshare" ("id")
);

CREATE INDEX IF NOT EXISTS "share_privatefiledirshare_0e7efed3" ON "share_privatefiledirshare" ("from_user");
CREATE INDEX IF NOT EXISTS "share_privatefiledirshare_2059abe4" ON "share_privatefiledirshare" ("repo_id");
CREATE INDEX IF NOT EXISTS "share_privatefiledirshare_bc172800" ON "share_privatefiledirshare" ("to_user");