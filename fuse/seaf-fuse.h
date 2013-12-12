#ifndef SEAF_FUSE_H
#define SEAF_FUSE_H

typedef struct _SeafileSession SeafileSession;
typedef struct _Seafile Seafile;

int parse_fuse_path (const char *path,
                     int *n_parts, char **user, char **repo_id, char **repo_path);

/* file.c */
int read_file(SeafileSession *seaf, Seafile *file, char *buf, size_t size,
              off_t offset, struct fuse_file_info *info);

/* getattr.c */
int do_getattr(SeafileSession *seaf, const char *path, struct stat *stbuf);

/* readdir.c */
int do_readdir(SeafileSession *seaf, const char *path, void *buf,
               fuse_fill_dir_t filler, off_t offset,
               struct fuse_file_info *info);

#endif /* SEAF_FUSE_H */
