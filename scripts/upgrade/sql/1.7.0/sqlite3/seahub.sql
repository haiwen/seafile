CREATE TABLE IF NOT EXISTS "message_usermessage" (
    "message_id" integer NOT NULL PRIMARY KEY,
    "message" varchar(512) NOT NULL,
    "from_email" varchar(75) NOT NULL,
    "to_email" varchar(75) NOT NULL,
    "timestamp" datetime NOT NULL,
    "ifread" bool NOT NULL
)
;
CREATE TABLE IF NOT EXISTS "message_usermsglastcheck" (
    "id" integer NOT NULL PRIMARY KEY,
    "check_time" datetime NOT NULL
)
;
CREATE INDEX IF NOT EXISTS "message_usermessage_8b1dd4eb" ON "message_usermessage" ("from_email");
CREATE INDEX IF NOT EXISTS "message_usermessage_590d1560" ON "message_usermessage" ("to_email");
