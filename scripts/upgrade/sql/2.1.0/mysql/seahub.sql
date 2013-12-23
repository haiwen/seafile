CREATE TABLE IF NOT EXISTS `captcha_captchastore` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `challenge` varchar(32) NOT NULL,
  `response` varchar(32) NOT NULL,
  `hashkey` varchar(40) NOT NULL,
  `expiration` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `hashkey` (`hashkey`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS `notifications_usernotification`;
CREATE TABLE IF NOT EXISTS `notifications_usernotification` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `to_user` varchar(255) NOT NULL,
  `msg_type` varchar(30) NOT NULL,
  `detail` longtext NOT NULL,
  `timestamp` datetime NOT NULL,
  `seen` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `notifications_usernotification_bc172800` (`to_user`),
  KEY `notifications_usernotification_265e5521` (`msg_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `options_useroptions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `option_key` varchar(50) NOT NULL,
  `option_val` varchar(50) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `options_useroptions_830a6ccb` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `profile_detailedprofile` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user` varchar(255) NOT NULL,
  `department` varchar(512) NOT NULL,
  `telephone` varchar(100) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `share_uploadlinkshare` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `repo_id` varchar(36) NOT NULL,
  `path` longtext NOT NULL,
  `token` varchar(10) NOT NULL,
  `ctime` datetime NOT NULL,
  `view_cnt` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `token` (`token`),
  KEY `share_uploadlinkshare_ee0cafa2` (`username`),
  KEY `share_uploadlinkshare_2059abe4` (`repo_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
