CREATE TABLE IF NOT EXISTS `post_office_attachment` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `file` varchar(100) NOT NULL,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `post_office_attachment_emails` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attachment_id` int(11) NOT NULL,
  `email_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `attachment_id` (`attachment_id`,`email_id`),
  KEY `post_office_attachment_emails_4be595e7` (`attachment_id`),
  KEY `post_office_attachment_emails_830a6ccb` (`email_id`),
  CONSTRAINT `attachment_id_refs_id_2d59d8fc` FOREIGN KEY (`attachment_id`) REFERENCES `post_office_attachment` (`id`),
  CONSTRAINT `email_id_refs_id_061d81d8` FOREIGN KEY (`email_id`) REFERENCES `post_office_email` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `post_office_email` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `from_email` varchar(254) NOT NULL,
  `to` longtext NOT NULL,
  `cc` longtext NOT NULL,
  `bcc` longtext NOT NULL,
  `subject` varchar(255) NOT NULL,
  `message` longtext NOT NULL,
  `html_message` longtext NOT NULL,
  `status` smallint(5) unsigned DEFAULT NULL,
  `priority` smallint(5) unsigned DEFAULT NULL,
  `created` datetime NOT NULL,
  `last_updated` datetime NOT NULL,
  `scheduled_time` datetime DEFAULT NULL,
  `headers` longtext,
  `template_id` int(11) DEFAULT NULL,
  `context` longtext,
  `backend_alias` varchar(64) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `post_office_email_48fb58bb` (`status`),
  KEY `post_office_email_63b5ea41` (`created`),
  KEY `post_office_email_470d4868` (`last_updated`),
  KEY `post_office_email_c83ff05e` (`scheduled_time`),
  KEY `post_office_email_43d23afc` (`template_id`),
  CONSTRAINT `template_id_refs_id_a5d97662` FOREIGN KEY (`template_id`) REFERENCES `post_office_emailtemplate` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `post_office_emailtemplate` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `description` longtext NOT NULL,
  `created` datetime NOT NULL,
  `last_updated` datetime NOT NULL,
  `subject` varchar(255) NOT NULL,
  `content` longtext NOT NULL,
  `html_content` longtext NOT NULL,
  `language` varchar(12) NOT NULL,
  `default_template_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `language` (`language`,`default_template_id`),
  KEY `post_office_emailtemplate_84c7951d` (`default_template_id`),
  CONSTRAINT `default_template_id_refs_id_a2bc649e` FOREIGN KEY (`default_template_id`) REFERENCES `post_office_emailtemplate` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `post_office_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email_id` int(11) NOT NULL,
  `date` datetime NOT NULL,
  `status` smallint(5) unsigned NOT NULL,
  `exception_type` varchar(255) NOT NULL,
  `message` longtext NOT NULL,
  PRIMARY KEY (`id`),
  KEY `post_office_log_830a6ccb` (`email_id`),
  CONSTRAINT `email_id_refs_id_3d87f587` FOREIGN KEY (`email_id`) REFERENCES `post_office_email` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `institutions_institution` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(200) NOT NULL,
  `create_time` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `institutions_institutionadmin` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user` varchar(254) NOT NULL,
  `institution_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `i_institution_id_5f792d6fe9a87ac9_fk_institutions_institution_id` (`institution_id`),
  CONSTRAINT `i_institution_id_5f792d6fe9a87ac9_fk_institutions_institution_id` FOREIGN KEY (`institution_id`) REFERENCES `institutions_institution` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

ALTER TABLE `sysadmin_extra_userloginlog` MODIFY `login_ip` VARCHAR(128);
