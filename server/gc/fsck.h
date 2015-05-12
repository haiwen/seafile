#ifndef SEAF_FSCK_H
#define SEAF_FSCK_H

int
seaf_fsck (GList *repo_id_list, gboolean repair, gboolean esync);

void export_file (GList *repo_id_list, const char *seafile_dir, char *export_path);

#endif
