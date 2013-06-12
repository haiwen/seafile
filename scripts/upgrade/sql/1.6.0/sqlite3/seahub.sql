CREATE TABLE IF NOT EXISTS "wiki_groupwiki" (
    "id" integer NOT NULL PRIMARY KEY,
    "group_id" integer NOT NULL UNIQUE,
    "repo_id" varchar(36) NOT NULL
);

CREATE TABLE IF NOT EXISTS "wiki_personalwiki" (
    "id" integer NOT NULL PRIMARY KEY,
    "username" varchar(256) NOT NULL UNIQUE,
    "repo_id" varchar(36) NOT NULL
);

CREATE TABLE IF NOT EXISTS "group_publicgroup" (
    "id" integer NOT NULL PRIMARY KEY,
    "group_id" integer NOT NULL
);
CREATE INDEX IF NOT EXISTS "group_publicgroup_bda51c3c" ON "group_publicgroup" ("group_id");

CREATE TABLE IF NOT EXISTS "base_filediscuss" (
    "id" integer NOT NULL PRIMARY KEY,
    "group_message_id" integer NOT NULL REFERENCES "group_groupmessage" ("id"),
    "repo_id" varchar(40) NOT NULL,
    "path" text NOT NULL,
    "path_hash" varchar(12) NOT NULL
);
CREATE INDEX IF NOT EXISTS "base_filediscuss_6844bd5a" ON "base_filediscuss" ("path_hash");
CREATE INDEX IF NOT EXISTS "base_filediscuss_c3e5da7c" ON "base_filediscuss" ("group_message_id");

CREATE TABLE IF NOT EXISTS "base_filelastmodifiedinfo" (
    "id" integer NOT NULL PRIMARY KEY,
    "repo_id" varchar(36) NOT NULL,
    "file_id" varchar(40) NOT NULL,
    "file_path" text NOT NULL,
    "file_path_hash" varchar(12) NOT NULL,
    "last_modified" bigint NOT NULL,
    "email" varchar(75) NOT NULL,
    UNIQUE ("repo_id", "file_path_hash")
);
CREATE INDEX IF NOT EXISTS "base_filelastmodifiedinfo_ca6f7e34" ON "base_filelastmodifiedinfo" ("repo_id");