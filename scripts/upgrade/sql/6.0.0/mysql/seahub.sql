ALTER TABLE api2_tokenv2 ADD COLUMN wiped_at DATETIME DEFAULT NULL;
ALTER TABLE api2_tokenv2 ADD COLUMN created_at DATETIME NOT NULL DEFAULT "1970-01-01 00:00:00";

CREATE TABLE IF NOT EXISTS `base_filecomment` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `repo_id` varchar(36) NOT NULL,
  `parent_path` longtext NOT NULL,
  `repo_id_parent_path_md5` varchar(100) NOT NULL,
  `item_name` longtext NOT NULL,
  `author` varchar(255) NOT NULL,
  `comment` longtext NOT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `base_filecomment_9a8c79bf` (`repo_id`),
  KEY `base_filecomment_c5bf47d4` (`repo_id_parent_path_md5`),
  KEY `base_filecomment_02bd92fa` (`author`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `termsandconditions_termsandconditions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `slug` varchar(50) NOT NULL,
  `name` longtext NOT NULL,
  `version_number` decimal(6,2) NOT NULL,
  `text` longtext,
  `info` longtext,
  `date_active` datetime DEFAULT NULL,
  `date_created` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `termsandconditions_termsandconditions_2dbcba41` (`slug`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `termsandconditions_usertermsandconditions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `ip_address` char(39) DEFAULT NULL,
  `date_accepted` datetime NOT NULL,
  `terms_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `termsandconditions_usertermsandcon_username_f4ab54cafa29322_uniq` (`username`,`terms_id`),
  KEY `e4da106203f3f13ff96409b55de6f515` (`terms_id`),
  CONSTRAINT `e4da106203f3f13ff96409b55de6f515` FOREIGN KEY (`terms_id`) REFERENCES `termsandconditions_termsandconditions` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `two_factor_totpdevice` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user` varchar(255) NOT NULL,
  `name` varchar(64) NOT NULL,
  `confirmed` tinyint(1) NOT NULL,
  `key` varchar(80) NOT NULL,
  `step` smallint(5) unsigned NOT NULL,
  `t0` bigint(20) NOT NULL,
  `digits` smallint(5) unsigned NOT NULL,
  `tolerance` smallint(5) unsigned NOT NULL,
  `drift` smallint(6) NOT NULL,
  `last_t` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user` (`user`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `two_factor_phonedevice` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user` varchar(255) NOT NULL,
  `name` varchar(64) NOT NULL,
  `confirmed` tinyint(1) NOT NULL,
  `number` varchar(40) NOT NULL,
  `key` varchar(40) NOT NULL,
  `method` varchar(4) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user` (`user`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8; 
    
CREATE TABLE IF NOT EXISTS `two_factor_staticdevice` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user` varchar(255) NOT NULL,
  `name` varchar(64) NOT NULL,
  `confirmed` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user` (`user`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `two_factor_statictoken` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `token` varchar(16) NOT NULL,
  `device_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `two_fac_device_id_55a7b345293a7c6c_fk_two_factor_staticdevice_id` (`device_id`),
  KEY `two_factor_statictoken_94a08da1` (`token`),
  CONSTRAINT `two_fac_device_id_55a7b345293a7c6c_fk_two_factor_staticdevice_id` FOREIGN KEY (`device_id`) REFERENCES `two_factor_staticdevice` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `invitations_invitation` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `token` varchar(40) NOT NULL,
  `inviter` varchar(255) NOT NULL,
  `accepter` varchar(255) NOT NULL,
  `invite_time` datetime NOT NULL,
  `accept_time` datetime DEFAULT NULL,
  `invite_type` varchar(20) NOT NULL,
  `expire_time` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `invitations_invitation_d5dd16f8` (`inviter`),
  KEY `invitations_invitation_token_1961fbb98c05e5fd_uniq` (`token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
