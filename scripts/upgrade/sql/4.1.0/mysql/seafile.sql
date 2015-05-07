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

CREATE TABLE IF NOT EXISTS RepoTrash (
    repo_id CHAR(36) PRIMARY KEY,
    repo_name VARCHAR(255),
    head_id CHAR(40),
    owner_id VARCHAR(255),
    size BIGINT(20),
    org_id INTEGER,
    INDEX(owner_id),
    INDEX(org_id)
) ENGINE=INNODB;
