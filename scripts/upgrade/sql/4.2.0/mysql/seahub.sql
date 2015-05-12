CREATE TABLE IF NOT EXISTS `base_clientlogintoken` (
  `token` varchar(32) NOT NULL,
  `username` varchar(255) NOT NULL,
  `timestamp` datetime NOT NULL,
  PRIMARY KEY (`token`),
  KEY `base_clientlogintoken_ee0cafa2` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `organizations_orgmemberquota` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `quota` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `organizations_orgmemberquota_944dadb6` (`org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

REPLACE INTO django_content_type VALUES(44,'client login token','base','clientlogintoken');
REPLACE INTO django_content_type VALUES(45,'org member quota','organizations','orgmemberquota');
