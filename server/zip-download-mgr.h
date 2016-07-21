#ifndef ZIP_DOWNLOAD_MGR_H
#define ZIP_DOWNLOAD_MGR_H

#include "seafile-object.h"

struct ZipDownloadMgrPriv;

typedef struct ZipDownloadMgr {
    struct ZipDownloadMgrPriv *priv;
} ZipDownloadMgr;

ZipDownloadMgr *
zip_download_mgr_new ();

int
zip_download_mgr_start_zip_task (ZipDownloadMgr *mgr,
                                 const char *token,
                                 SeafileWebAccess *info,
                                 GError **error);

char *
zip_download_mgr_query_zip_progress (ZipDownloadMgr *mgr,
                                     const char *token, GError **error);

char *
zip_download_mgr_get_zip_file_path (ZipDownloadMgr *mgr,
                                    const char *token);

void
zip_download_mgr_del_zip_progress (ZipDownloadMgr *mgr,
                                   const char *token);

#endif
