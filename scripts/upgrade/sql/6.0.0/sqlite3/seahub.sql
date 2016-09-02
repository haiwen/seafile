CREATE TABLE IF NOT EXISTS "base_filecomment" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "repo_id" varchar(36) NOT NULL, "parent_path" text NOT NULL, "repo_id_parent_path_md5" varchar(100) NOT NULL, "item_name" text NOT NULL, "author" varchar(255) NOT NULL, "comment" text NOT NULL, "created_at" datetime NOT NULL, "updated_at" datetime NOT NULL);
CREATE INDEX IF NOT EXISTS "base_filecomment_02bd92fa" ON "base_filecomment" ("author");
CREATE INDEX IF NOT EXISTS "base_filecomment_9a8c79bf" ON "base_filecomment" ("repo_id");
CREATE INDEX IF NOT EXISTS "base_filecomment_c5bf47d4" ON "base_filecomment" ("repo_id_parent_path_md5");

CREATE TABLE IF NOT EXISTS "termsandconditions_termsandconditions" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "slug" varchar(50) NOT NULL, "name" text NOT NULL, "version_number" decimal NOT NULL, "text" text NULL, "info" text NULL, "date_active" datetime NULL, "date_created" datetime NOT NULL);
CREATE INDEX IF NOT EXISTS "termsandconditions_termsandconditions_2dbcba41" ON "termsandconditions_termsandconditions" ("slug");

CREATE TABLE IF NOT EXISTS "termsandconditions_usertermsandconditions" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(255) NOT NULL, "ip_address" char(39) NULL, "date_accepted" datetime NOT NULL, "terms_id" integer NOT NULL REFERENCES "termsandconditions_termsandconditions" ("id"), UNIQUE ("username", "terms_id"));
CREATE INDEX IF NOT EXISTS "termsandconditions_usertermsandconditions_2ab34720" ON "termsandconditions_usertermsandconditions" ("terms_id");

CREATE TABLE IF NOT EXISTS "two_factor_phonedevice" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "user" varchar(255) NOT NULL UNIQUE, "name" varchar(64) NOT NULL, "confirmed" bool NOT NULL, "number" varchar(40) NOT NULL, "key" varchar(40) NOT NULL, "method" varchar(4) NOT NULL);
CREATE TABLE IF NOT EXISTS "two_factor_staticdevice" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "user" varchar(255) NOT NULL UNIQUE, "name" varchar(64) NOT NULL, "confirmed" bool NOT NULL);
CREATE TABLE IF NOT EXISTS "two_factor_statictoken" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "token" varchar(16) NOT NULL, "device_id" integer NOT NULL REFERENCES "two_factor_staticdevice" ("id"));
CREATE TABLE IF NOT EXISTS "two_factor_totpdevice" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "user" varchar(255) NOT NULL UNIQUE, "name" varchar(64) NOT NULL, "confirmed" bool NOT NULL, "key" varchar(80) NOT NULL, "step" smallint unsigned NOT NULL, "t0" bigint NOT NULL, "digits" smallint unsigned NOT NULL, "tolerance" smallint unsigned NOT NULL, "drift" smallint NOT NULL, "last_t" bigint NOT NULL);
CREATE INDEX IF NOT EXISTS "two_factor_statictoken_94a08da1" ON "two_factor_statictoken" ("token");
CREATE INDEX IF NOT EXISTS "two_factor_statictoken_9379346c" ON "two_factor_statictoken" ("device_id");

CREATE TABLE IF NOT EXISTS "invitations_invitation" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "token" varchar(40) NOT NULL, "inviter" varchar(255) NOT NULL, "accepter" varchar(255) NOT NULL, "invite_time" datetime NOT NULL, "accept_time" datetime NULL, "invite_type" varchar(20) NOT NULL, "expire_time" datetime NOT NULL);
CREATE INDEX IF NOT EXISTS "invitations_invitation_94a08da1" ON "invitations_invitation" ("token");
CREATE INDEX IF NOT EXISTS "invitations_invitation_d5dd16f8" ON "invitations_invitation" ("inviter");

ALTER TABLE api2_tokenv2 ADD COLUMN wiped_at datetime DEFAULT NULL;
ALTER TABLE api2_tokenv2 ADD COLUMN created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00';
