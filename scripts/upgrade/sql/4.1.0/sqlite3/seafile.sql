CREATE INDEX IF NOT EXISTS FromEmailIndex on SharedRepo (from_email);
CREATE INDEX IF NOT EXISTS ToEmailIndex on SharedRepo (to_email);

CREATE TABLE IF NOT EXISTS RepoTrash (
    repo_id CHAR(36) PRIMARY KEY,
    repo_name VARCHAR(255),
    head_id CHAR(40),
    owner_id VARCHAR(255),
    size BIGINT UNSIGNED,
    org_id INTEGER
);

CREATE INDEX IF NOT EXISTS repotrash_owner_id_idx ON RepoTrash(owner_id);
CREATE INDEX IF NOT EXISTS repotrash_org_id_idx ON RepoTrash(org_id);
