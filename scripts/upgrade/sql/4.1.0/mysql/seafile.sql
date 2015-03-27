ALTER TABLE SharedRepo MODIFY from_email VARCHAR(255);
ALTER TABLE SharedRepo MODIFY to_email VARCHAR(255);
ALTER TABLE SharedRepo ADD INDEX (from_email);
ALTER TABLE SharedRepo ADD INDEX (to_email);

CREATE TABLE IF NOT EXISTS OrgSharedRepo (
    id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT,
    org_id INT,
    repo_id CHAR(37) ,
    from_email VARCHAR(255),
    to_email VARCHAR(255),
    permission CHAR(15),
    INDEX (org_id, repo_id),
    INDEX(from_email),
    INDEX(to_email)
) ENGINE=INNODB;

ALTER TABLE OrgSharedRepo MODIFY from_email VARCHAR(255);
ALTER TABLE OrgSharedRepo MODIFY to_email VARCHAR(255);
