#ifndef GC_CORE_H
#define GC_CORE_H

int gc_core_run (GList *repo_id_list, int dry_run, int verbose);

void
delete_garbaged_repos (int dry_run);

#endif
