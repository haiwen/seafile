CREATE TABLE IF NOT EXISTS api2_tokenv2 (
"key" varchar(40) NOT NULL CONSTRAINT primary_key PRIMARY KEY,
"user" varchar(255) NOT NULL,
"platform" varchar(32) NOT NULL,
"device_id" varchar(40) NOT NULL,
"device_name" varchar(40) NOT NULL,
"platform_version" varchar(16) NOT NULL,
"client_version" varchar(16) NOT NULL,
"last_accessed" timestamp NOT NULL,
"last_login_ip" char(39) DEFAULT NULL,
CONSTRAINT unique_key UNIQUE  ("user", "platform", "device_id")
);
