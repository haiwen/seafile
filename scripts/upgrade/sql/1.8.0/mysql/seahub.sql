-- seahub
ALTER TABLE group_groupmessage MODIFY message varchar(2048);
ALTER TABLE group_messagereply MODIFY message varchar(2048);

CREATE TABLE IF NOT EXISTS `share_privatefiledirshare` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `from_user` varchar(255) NOT NULL,
  `to_user` varchar(255) NOT NULL,
  `repo_id` varchar(36) NOT NULL,
  `path` longtext NOT NULL,
  `token` varchar(10) NOT NULL,
  `permission` varchar(5) NOT NULL,
  `s_type` varchar(5) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `token` (`token`),
  KEY `share_privatefiledirshare_0e7efed3` (`from_user`),
  KEY `share_privatefiledirshare_bc172800` (`to_user`),
  KEY `share_privatefiledirshare_2059abe4` (`repo_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `message_usermsgattachment` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_msg_id` int(11) NOT NULL,
  `priv_file_dir_share_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `message_usermsgattachment_72f290f5` (`user_msg_id`),
  KEY `message_usermsgattachment_cee41a9a` (`priv_file_dir_share_id`),
  CONSTRAINT `priv_file_dir_share_id_refs_id_163f8f83` FOREIGN KEY (`priv_file_dir_share_id`) REFERENCES `share_privatefiledirshare` (`id`),
  CONSTRAINT `user_msg_id_refs_message_id_debb82ad` FOREIGN KEY (`user_msg_id`) REFERENCES `message_usermessage` (`message_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;