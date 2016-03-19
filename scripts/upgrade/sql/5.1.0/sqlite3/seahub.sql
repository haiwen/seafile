CREATE TABLE IF NOT EXISTS "post_office_attachment" (
    "id" integer NOT NULL PRIMARY KEY,
    "file" varchar(100) NOT NULL,
    "name" varchar(255) NOT NULL
);
CREATE TABLE IF NOT EXISTS "post_office_attachment_emails" (
    "id" integer NOT NULL PRIMARY KEY,
    "attachment_id" integer NOT NULL,
    "email_id" integer NOT NULL REFERENCES "post_office_email" ("id"),
    UNIQUE ("attachment_id", "email_id")
);
CREATE TABLE IF NOT EXISTS "post_office_email" (
    "id" integer NOT NULL PRIMARY KEY,
    "from_email" varchar(254) NOT NULL,
    "to" text NOT NULL,
    "cc" text NOT NULL,
    "bcc" text NOT NULL,
    "subject" varchar(255) NOT NULL,
    "message" text NOT NULL,
    "html_message" text NOT NULL,
    "status" smallint unsigned,
    "priority" smallint unsigned,
    "created" datetime NOT NULL,
    "last_updated" datetime NOT NULL,
    "scheduled_time" datetime,
    "headers" text,
    "template_id" integer,
    "context" text,
    "backend_alias" varchar(64) NOT NULL
);
CREATE TABLE IF NOT EXISTS "post_office_emailtemplate" (
    "id" integer NOT NULL PRIMARY KEY,
    "name" varchar(255) NOT NULL,
    "description" text NOT NULL,
    "created" datetime NOT NULL,
    "last_updated" datetime NOT NULL,
    "subject" varchar(255) NOT NULL,
    "content" text NOT NULL,
    "html_content" text NOT NULL,
    "language" varchar(12) NOT NULL,
    "default_template_id" integer,
    UNIQUE ("language", "default_template_id")
);
CREATE TABLE IF NOT EXISTS "post_office_log" (
    "id" integer NOT NULL PRIMARY KEY,
    "email_id" integer NOT NULL REFERENCES "post_office_email" ("id"),
    "date" datetime NOT NULL,
    "status" smallint unsigned NOT NULL,
    "exception_type" varchar(255) NOT NULL,
    "message" text NOT NULL
);
CREATE TABLE IF NOT EXISTS "institutions_institution" (
       "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
       "name" varchar(200) NOT NULL,
       "create_time" datetime NOT NULL
);
CREATE TABLE IF NOT EXISTS "institutions_institutionadmin" (
       "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
       "user" varchar(254) NOT NULL,
       "institution_id" integer NOT NULL REFERENCES "institutions_institution" ("id")
);

CREATE INDEX IF NOT EXISTS "post_office_attachment_emails_4be595e7" ON "post_office_attachment_emails" ("attachment_id");
CREATE INDEX IF NOT EXISTS  "post_office_attachment_emails_830a6ccb" ON "post_office_attachment_emails" ("email_id");
CREATE INDEX IF NOT EXISTS  "post_office_email_43d23afc" ON "post_office_email" ("template_id");
CREATE INDEX IF NOT EXISTS  "post_office_email_470d4868" ON "post_office_email" ("last_updated");
CREATE INDEX IF NOT EXISTS  "post_office_email_48fb58bb" ON "post_office_email" ("status");
CREATE INDEX IF NOT EXISTS  "post_office_email_63b5ea41" ON "post_office_email" ("created");
CREATE INDEX IF NOT EXISTS  "post_office_email_c83ff05e" ON "post_office_email" ("scheduled_time");
CREATE INDEX IF NOT EXISTS  "post_office_emailtemplate_84c7951d" ON "post_office_emailtemplate" ("default_template_id");
CREATE INDEX IF NOT EXISTS  "post_office_log_830a6ccb" ON "post_office_log" ("email_id");
CREATE INDEX "institutions_institutionadmin_a964baeb" ON "institutions_institutionadmin" ("institution_id");
