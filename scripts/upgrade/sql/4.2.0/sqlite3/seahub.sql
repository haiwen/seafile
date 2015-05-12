CREATE TABLE IF NOT EXISTS "base_clientlogintoken" (
    "token" varchar(32) NOT NULL PRIMARY KEY,
    "username" varchar(255) NOT NULL,
    "timestamp" datetime NOT NULL
);

CREATE INDEX IF NOT EXISTS "base_clientlogintoken_ee0cafa2" ON "base_clientlogintoken" ("username");

CREATE TABLE IF NOT EXISTS "organizations_orgmemberquota" (
    "id" integer NOT NULL PRIMARY KEY,
    "org_id" integer NOT NULL,
    "quota" integer NOT NULL
);

CREATE INDEX IF NOT EXISTS "organizations_orgmemberquota_944dadb6" ON "organizations_orgmemberquota" ("org_id");

REPLACE INTO "django_content_type" VALUES(44,'client login token','base','clientlogintoken');
REPLACE INTO "django_content_type" VALUES(45,'org member quota','organizations','orgmemberquota');
