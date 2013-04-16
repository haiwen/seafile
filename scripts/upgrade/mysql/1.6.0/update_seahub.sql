CREATE TABLE IF NOT EXISTS `wiki_groupwiki` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `group_id` int(11) NOT NULL,
  `repo_id` varchar(36) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `group_id` (`group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `wiki_personalwiki` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `repo_id` varchar(36) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `group_publicgroup` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `group_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `group_publicgroup_425ae3c4` (`group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `base_filediscuss` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `group_message_id` int(11) NOT NULL,
  `repo_id` varchar(36) NOT NULL,
  `path` longtext NOT NULL,
  `path_hash` varchar(12) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `base_filediscuss_3c1a2584` (`group_message_id`),
  KEY `base_filediscuss_6844bd5a` (`path_hash`),
  CONSTRAINT `group_message_id_refs_id_2ade200f` FOREIGN KEY (`group_message_id`) REFERENCES `group_groupmessage` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `base_filelastmodifiedinfo` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `repo_id` varchar(36) NOT NULL,
  `file_id` varchar(40) NOT NULL,
  `file_path` longtext NOT NULL,
  `file_path_hash` varchar(12) NOT NULL,
  `last_modified` bigint(20) NOT NULL,
  `email` varchar(75) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `repo_id` (`repo_id`,`file_path_hash`),
  KEY `base_filelastmodifiedinfo_359081cc` (`repo_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ;