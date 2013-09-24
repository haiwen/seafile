#ifndef SEAF_FUSE_H
#define SEAF_FUSE_H

typedef struct _SeafileSession SeafileSession;
typedef struct _Seafile Seafile;

/* file.c */
int read_file(SeafileSession *seaf, Seafile *file, char *buf, size_t size,
              off_t offset, struct fuse_file_info *info);

/* getattr.c */
int getattr_root(SeafileSession *seaf, const char *path, struct stat *stbuf);
int getattr_repo(SeafileSession *seaf, const char *path, struct stat *stbuf);

/* readdir.c */
int readdir_root(SeafileSession *seaf, const char *path, void *buf,
                 fuse_fill_dir_t filler, off_t offset,
                 struct fuse_file_info *info);
int readdir_repo(SeafileSession *seaf, const char *path, void *buf,
                 fuse_fill_dir_t filler, off_t offset,
                 struct fuse_file_info *info);

#endif /* SEAF_FUSE_H */
