CREATE TABLE IF NOT EXISTS `constance_config` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `key` varchar(255) NOT NULL,
  `value` longtext NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `key` (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

ALTER TABLE `profile_profile` ADD `login_id` varchar(225) DEFAULT NULL;
ALTER TABLE `profile_profile` ADD `contact_email` varchar(225) DEFAULT NULL;
ALTER TABLE `profile_profile` ADD `institution` varchar(225) DEFAULT NULL;

ALTER TABLE `profile_profile` ADD UNIQUE INDEX (`login_id`);
ALTER TABLE `profile_profile` ADD INDEX (`contact_email`);
ALTER TABLE `profile_profile` ADD INDEX (`institution`);


