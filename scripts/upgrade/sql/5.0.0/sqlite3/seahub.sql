CREATE TABLE IF NOT EXISTS "constance_config" (
    "id" integer NOT NULL PRIMARY KEY,
    "key" varchar(255) NOT NULL UNIQUE,
    "value" text NOT NULL
);

ALTER TABLE "profile_profile" ADD COLUMN "login_id" varchar(225);
ALTER TABLE "profile_profile" ADD COLUMN "contact_email" varchar(225);
ALTER TABLE "profile_profile" ADD COLUMN "institution" varchar(225);

CREATE UNIQUE INDEX "profile_profile_1b43c217" ON "profile_profile" ("login_id");
CREATE INDEX "profile_profile_3b46cb17" ON "profile_profile" ("contact_email");
CREATE INDEX "profile_profile_71bbc151" ON "profile_profile" ("institution");
