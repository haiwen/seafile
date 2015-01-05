alter table "message_usermessage" add column "sender_deleted_at" datetime;
alter table "message_usermessage" add column "recipient_deleted_at" datetime;
alter table "share_fileshare" add column "password" varchar(128);
alter table "share_fileshare" add column "expire_date" datetime;
alter table "share_uploadlinkshare" add column "password" varchar(128);
alter table "share_uploadlinkshare" add column "expire_date" datetime;
alter table "profile_profile" add column "lang_code" varchar(50);

CREATE TABLE IF NOT EXISTS "share_orgfileshare" (
    "id" integer NOT NULL PRIMARY KEY,
    "org_id" integer NOT NULL,
    "file_share_id" integer NOT NULL UNIQUE REFERENCES "share_fileshare" ("id")
);
CREATE INDEX IF NOT EXISTS "share_orgfileshare_944dadb6" ON "share_orgfileshare" ("org_id");

CREATE INDEX IF NOT EXISTS "base_userstarredfiles_email" on "base_userstarredfiles" ("email");
