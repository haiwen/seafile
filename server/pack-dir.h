#ifndef PACK_DIR_H
#define PACK_DIR_H

/* Pack a seafile directory to a zipped archive, saved in a temporary file.
   Return the path of this temporary file.
 */
char *pack_dir (const char *repo_id,
                int repo_version,
                const char *dirname,
                const char *root_id,
                SeafileCrypt *crypt,
                gboolean is_windows);
#endif
