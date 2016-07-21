#ifndef PACK_DIR_H
#define PACK_DIR_H

/* Pack a seafile directory to a zipped archive, saved in a temporary file.
   Return the path of this temporary file.
 */

typedef struct Progress {
    int zipped;
    int total;
    char *zip_file_path;
    gint64 expire_ts;
} Progress;

int
pack_files (const char *store_id,
            int repo_version,
            const char *dirname,
            void *internal,
            SeafileCrypt *crypt,
            gboolean is_windows,
            Progress *progress);

#endif
