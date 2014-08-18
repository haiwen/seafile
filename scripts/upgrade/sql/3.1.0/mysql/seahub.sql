alter table message_usermessage add column sender_deleted_at datetime DEFAULT NULL;
alter table message_usermessage add column recipient_deleted_at datetime DEFAULT NULL;

alter table share_fileshare add column password varchar(128);
alter table share_fileshare add column expire_date datetime;
alter table share_uploadlinkshare add column password varchar(128);
alter table share_uploadlinkshare add column expire_date datetime;
alter table profile_profile add column lang_code varchar(50) DEFAULT NULL;

CREATE TABLE IF NOT EXISTS `share_orgfileshare` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `file_share_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `file_share_id` (`file_share_id`),
  KEY `share_orgfileshare_944dadb6` (`org_id`),
  CONSTRAINT `file_share_id_refs_id_bd2fd9f8` FOREIGN KEY (`file_share_id`) REFERENCES `share_fileshare` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

ALTER TABLE `base_userstarredfiles` ADD INDEX `base_userstarredfiles_email` (email);
