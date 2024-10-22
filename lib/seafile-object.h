/* seafile-object.h generated by valac 0.56.1, the Vala compiler, do not modify */

#ifndef __SEAFILE_OBJECT_H__
#define __SEAFILE_OBJECT_H__

#include <glib-object.h>
#include <glib.h>

G_BEGIN_DECLS

#if !defined(VALA_EXTERN)
#if defined(_MSC_VER)
#define VALA_EXTERN __declspec(dllexport) extern
#elif __GNUC__ >= 4
#define VALA_EXTERN __attribute__((visibility("default"))) extern
#else
#define VALA_EXTERN extern
#endif
#endif

#define SEAFILE_TYPE_REPO (seafile_repo_get_type ())
#define SEAFILE_REPO(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_REPO, SeafileRepo))
#define SEAFILE_REPO_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_REPO, SeafileRepoClass))
#define SEAFILE_IS_REPO(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_REPO))
#define SEAFILE_IS_REPO_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_REPO))
#define SEAFILE_REPO_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_REPO, SeafileRepoClass))

typedef struct _SeafileRepo SeafileRepo;
typedef struct _SeafileRepoClass SeafileRepoClass;
typedef struct _SeafileRepoPrivate SeafileRepoPrivate;

#define SEAFILE_TYPE_SYNC_TASK (seafile_sync_task_get_type ())
#define SEAFILE_SYNC_TASK(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_SYNC_TASK, SeafileSyncTask))
#define SEAFILE_SYNC_TASK_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_SYNC_TASK, SeafileSyncTaskClass))
#define SEAFILE_IS_SYNC_TASK(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_SYNC_TASK))
#define SEAFILE_IS_SYNC_TASK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_SYNC_TASK))
#define SEAFILE_SYNC_TASK_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_SYNC_TASK, SeafileSyncTaskClass))

typedef struct _SeafileSyncTask SeafileSyncTask;
typedef struct _SeafileSyncTaskClass SeafileSyncTaskClass;
typedef struct _SeafileSyncTaskPrivate SeafileSyncTaskPrivate;

#define SEAFILE_TYPE_SESSION_INFO (seafile_session_info_get_type ())
#define SEAFILE_SESSION_INFO(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_SESSION_INFO, SeafileSessionInfo))
#define SEAFILE_SESSION_INFO_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_SESSION_INFO, SeafileSessionInfoClass))
#define SEAFILE_IS_SESSION_INFO(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_SESSION_INFO))
#define SEAFILE_IS_SESSION_INFO_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_SESSION_INFO))
#define SEAFILE_SESSION_INFO_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_SESSION_INFO, SeafileSessionInfoClass))

typedef struct _SeafileSessionInfo SeafileSessionInfo;
typedef struct _SeafileSessionInfoClass SeafileSessionInfoClass;
typedef struct _SeafileSessionInfoPrivate SeafileSessionInfoPrivate;

#define SEAFILE_TYPE_DIFF_ENTRY (seafile_diff_entry_get_type ())
#define SEAFILE_DIFF_ENTRY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_DIFF_ENTRY, SeafileDiffEntry))
#define SEAFILE_DIFF_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_DIFF_ENTRY, SeafileDiffEntryClass))
#define SEAFILE_IS_DIFF_ENTRY(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_DIFF_ENTRY))
#define SEAFILE_IS_DIFF_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_DIFF_ENTRY))
#define SEAFILE_DIFF_ENTRY_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_DIFF_ENTRY, SeafileDiffEntryClass))

typedef struct _SeafileDiffEntry SeafileDiffEntry;
typedef struct _SeafileDiffEntryClass SeafileDiffEntryClass;
typedef struct _SeafileDiffEntryPrivate SeafileDiffEntryPrivate;

#define SEAFILE_TYPE_ENCRYPTION_INFO (seafile_encryption_info_get_type ())
#define SEAFILE_ENCRYPTION_INFO(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_ENCRYPTION_INFO, SeafileEncryptionInfo))
#define SEAFILE_ENCRYPTION_INFO_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_ENCRYPTION_INFO, SeafileEncryptionInfoClass))
#define SEAFILE_IS_ENCRYPTION_INFO(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_ENCRYPTION_INFO))
#define SEAFILE_IS_ENCRYPTION_INFO_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_ENCRYPTION_INFO))
#define SEAFILE_ENCRYPTION_INFO_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_ENCRYPTION_INFO, SeafileEncryptionInfoClass))

typedef struct _SeafileEncryptionInfo SeafileEncryptionInfo;
typedef struct _SeafileEncryptionInfoClass SeafileEncryptionInfoClass;
typedef struct _SeafileEncryptionInfoPrivate SeafileEncryptionInfoPrivate;

#define SEAFILE_TYPE_FILE_SYNC_ERROR (seafile_file_sync_error_get_type ())
#define SEAFILE_FILE_SYNC_ERROR(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_FILE_SYNC_ERROR, SeafileFileSyncError))
#define SEAFILE_FILE_SYNC_ERROR_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_FILE_SYNC_ERROR, SeafileFileSyncErrorClass))
#define SEAFILE_IS_FILE_SYNC_ERROR(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_FILE_SYNC_ERROR))
#define SEAFILE_IS_FILE_SYNC_ERROR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_FILE_SYNC_ERROR))
#define SEAFILE_FILE_SYNC_ERROR_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_FILE_SYNC_ERROR, SeafileFileSyncErrorClass))

typedef struct _SeafileFileSyncError SeafileFileSyncError;
typedef struct _SeafileFileSyncErrorClass SeafileFileSyncErrorClass;
typedef struct _SeafileFileSyncErrorPrivate SeafileFileSyncErrorPrivate;

#define SEAFILE_TYPE_TASK (seafile_task_get_type ())
#define SEAFILE_TASK(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_TASK, SeafileTask))
#define SEAFILE_TASK_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_TASK, SeafileTaskClass))
#define SEAFILE_IS_TASK(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_TASK))
#define SEAFILE_IS_TASK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_TASK))
#define SEAFILE_TASK_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_TASK, SeafileTaskClass))

typedef struct _SeafileTask SeafileTask;
typedef struct _SeafileTaskClass SeafileTaskClass;
typedef struct _SeafileTaskPrivate SeafileTaskPrivate;

#define SEAFILE_TYPE_CLONE_TASK (seafile_clone_task_get_type ())
#define SEAFILE_CLONE_TASK(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_CLONE_TASK, SeafileCloneTask))
#define SEAFILE_CLONE_TASK_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_CLONE_TASK, SeafileCloneTaskClass))
#define SEAFILE_IS_CLONE_TASK(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_CLONE_TASK))
#define SEAFILE_IS_CLONE_TASK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_CLONE_TASK))
#define SEAFILE_CLONE_TASK_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_CLONE_TASK, SeafileCloneTaskClass))

typedef struct _SeafileCloneTask SeafileCloneTask;
typedef struct _SeafileCloneTaskClass SeafileCloneTaskClass;
typedef struct _SeafileCloneTaskPrivate SeafileCloneTaskPrivate;

struct _SeafileRepo {
	GObject parent_instance;
	SeafileRepoPrivate * priv;
	gchar _id[37];
	gchar* _name;
	gchar* _desc;
	gchar* _worktree;
	gchar* _relay_id;
};

struct _SeafileRepoClass {
	GObjectClass parent_class;
};

struct _SeafileSyncTask {
	GObject parent_instance;
	SeafileSyncTaskPrivate * priv;
};

struct _SeafileSyncTaskClass {
	GObjectClass parent_class;
};

struct _SeafileSessionInfo {
	GObject parent_instance;
	SeafileSessionInfoPrivate * priv;
};

struct _SeafileSessionInfoClass {
	GObjectClass parent_class;
};

struct _SeafileDiffEntry {
	GObject parent_instance;
	SeafileDiffEntryPrivate * priv;
};

struct _SeafileDiffEntryClass {
	GObjectClass parent_class;
};

struct _SeafileEncryptionInfo {
	GObject parent_instance;
	SeafileEncryptionInfoPrivate * priv;
};

struct _SeafileEncryptionInfoClass {
	GObjectClass parent_class;
};

struct _SeafileFileSyncError {
	GObject parent_instance;
	SeafileFileSyncErrorPrivate * priv;
};

struct _SeafileFileSyncErrorClass {
	GObjectClass parent_class;
};

struct _SeafileTask {
	GObject parent_instance;
	SeafileTaskPrivate * priv;
};

struct _SeafileTaskClass {
	GObjectClass parent_class;
};

struct _SeafileCloneTask {
	GObject parent_instance;
	SeafileCloneTaskPrivate * priv;
};

struct _SeafileCloneTaskClass {
	GObjectClass parent_class;
};

VALA_EXTERN GType seafile_repo_get_type (void) G_GNUC_CONST ;
G_DEFINE_AUTOPTR_CLEANUP_FUNC (SeafileRepo, g_object_unref)
VALA_EXTERN SeafileRepo* seafile_repo_new (void);
VALA_EXTERN SeafileRepo* seafile_repo_construct (GType object_type);
VALA_EXTERN const gchar* seafile_repo_get_id (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_id (SeafileRepo* self,
                          const gchar* value);
VALA_EXTERN const gchar* seafile_repo_get_name (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_name (SeafileRepo* self,
                            const gchar* value);
VALA_EXTERN const gchar* seafile_repo_get_desc (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_desc (SeafileRepo* self,
                            const gchar* value);
VALA_EXTERN gint seafile_repo_get_version (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_version (SeafileRepo* self,
                               gint value);
VALA_EXTERN gint seafile_repo_get_last_modify (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_last_modify (SeafileRepo* self,
                                   gint value);
VALA_EXTERN gint64 seafile_repo_get_size (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_size (SeafileRepo* self,
                            gint64 value);
VALA_EXTERN gint64 seafile_repo_get_file_count (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_file_count (SeafileRepo* self,
                                  gint64 value);
VALA_EXTERN const gchar* seafile_repo_get_head_cmmt_id (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_head_cmmt_id (SeafileRepo* self,
                                    const gchar* value);
VALA_EXTERN const gchar* seafile_repo_get_root (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_root (SeafileRepo* self,
                            const gchar* value);
VALA_EXTERN const gchar* seafile_repo_get_repo_id (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_repo_id (SeafileRepo* self,
                               const gchar* value);
VALA_EXTERN const gchar* seafile_repo_get_repo_name (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_repo_name (SeafileRepo* self,
                                 const gchar* value);
VALA_EXTERN const gchar* seafile_repo_get_repo_desc (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_repo_desc (SeafileRepo* self,
                                 const gchar* value);
VALA_EXTERN gint seafile_repo_get_last_modified (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_last_modified (SeafileRepo* self,
                                     gint value);
VALA_EXTERN gboolean seafile_repo_get_encrypted (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_encrypted (SeafileRepo* self,
                                 gboolean value);
VALA_EXTERN const gchar* seafile_repo_get_magic (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_magic (SeafileRepo* self,
                             const gchar* value);
VALA_EXTERN gint seafile_repo_get_enc_version (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_enc_version (SeafileRepo* self,
                                   gint value);
VALA_EXTERN const gchar* seafile_repo_get_random_key (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_random_key (SeafileRepo* self,
                                  const gchar* value);
VALA_EXTERN const gchar* seafile_repo_get_salt (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_salt (SeafileRepo* self,
                            const gchar* value);
VALA_EXTERN const gchar* seafile_repo_get_worktree (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_worktree (SeafileRepo* self,
                                const gchar* value);
VALA_EXTERN const gchar* seafile_repo_get_relay_id (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_relay_id (SeafileRepo* self,
                                const gchar* value);
VALA_EXTERN gint seafile_repo_get_last_sync_time (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_last_sync_time (SeafileRepo* self,
                                      gint value);
VALA_EXTERN gboolean seafile_repo_get_auto_sync (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_auto_sync (SeafileRepo* self,
                                 gboolean value);
VALA_EXTERN gboolean seafile_repo_get_worktree_invalid (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_worktree_invalid (SeafileRepo* self,
                                        gboolean value);
VALA_EXTERN gboolean seafile_repo_get_is_virtual (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_is_virtual (SeafileRepo* self,
                                  gboolean value);
VALA_EXTERN const gchar* seafile_repo_get_origin_repo_id (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_origin_repo_id (SeafileRepo* self,
                                      const gchar* value);
VALA_EXTERN const gchar* seafile_repo_get_origin_repo_name (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_origin_repo_name (SeafileRepo* self,
                                        const gchar* value);
VALA_EXTERN const gchar* seafile_repo_get_origin_path (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_origin_path (SeafileRepo* self,
                                   const gchar* value);
VALA_EXTERN gboolean seafile_repo_get_is_original_owner (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_is_original_owner (SeafileRepo* self,
                                         gboolean value);
VALA_EXTERN const gchar* seafile_repo_get_virtual_perm (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_virtual_perm (SeafileRepo* self,
                                    const gchar* value);
VALA_EXTERN const gchar* seafile_repo_get_store_id (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_store_id (SeafileRepo* self,
                                const gchar* value);
VALA_EXTERN gboolean seafile_repo_get_is_corrupted (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_is_corrupted (SeafileRepo* self,
                                    gboolean value);
VALA_EXTERN gboolean seafile_repo_get_repaired (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_repaired (SeafileRepo* self,
                                gboolean value);
VALA_EXTERN const gchar* seafile_repo_get_share_type (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_share_type (SeafileRepo* self,
                                  const gchar* value);
VALA_EXTERN const gchar* seafile_repo_get_permission (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_permission (SeafileRepo* self,
                                  const gchar* value);
VALA_EXTERN const gchar* seafile_repo_get_user (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_user (SeafileRepo* self,
                            const gchar* value);
VALA_EXTERN gint seafile_repo_get_group_id (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_group_id (SeafileRepo* self,
                                gint value);
VALA_EXTERN gboolean seafile_repo_get_is_shared (SeafileRepo* self);
VALA_EXTERN void seafile_repo_set_is_shared (SeafileRepo* self,
                                 gboolean value);
VALA_EXTERN GType seafile_sync_task_get_type (void) G_GNUC_CONST ;
G_DEFINE_AUTOPTR_CLEANUP_FUNC (SeafileSyncTask, g_object_unref)
VALA_EXTERN SeafileSyncTask* seafile_sync_task_new (void);
VALA_EXTERN SeafileSyncTask* seafile_sync_task_construct (GType object_type);
VALA_EXTERN gboolean seafile_sync_task_get_force_upload (SeafileSyncTask* self);
VALA_EXTERN void seafile_sync_task_set_force_upload (SeafileSyncTask* self,
                                         gboolean value);
VALA_EXTERN const gchar* seafile_sync_task_get_repo_id (SeafileSyncTask* self);
VALA_EXTERN void seafile_sync_task_set_repo_id (SeafileSyncTask* self,
                                    const gchar* value);
VALA_EXTERN const gchar* seafile_sync_task_get_state (SeafileSyncTask* self);
VALA_EXTERN void seafile_sync_task_set_state (SeafileSyncTask* self,
                                  const gchar* value);
VALA_EXTERN gint seafile_sync_task_get_error (SeafileSyncTask* self);
VALA_EXTERN void seafile_sync_task_set_error (SeafileSyncTask* self,
                                  gint value);
VALA_EXTERN GType seafile_session_info_get_type (void) G_GNUC_CONST ;
G_DEFINE_AUTOPTR_CLEANUP_FUNC (SeafileSessionInfo, g_object_unref)
VALA_EXTERN SeafileSessionInfo* seafile_session_info_new (void);
VALA_EXTERN SeafileSessionInfo* seafile_session_info_construct (GType object_type);
VALA_EXTERN const gchar* seafile_session_info_get_datadir (SeafileSessionInfo* self);
VALA_EXTERN void seafile_session_info_set_datadir (SeafileSessionInfo* self,
                                       const gchar* value);
VALA_EXTERN GType seafile_diff_entry_get_type (void) G_GNUC_CONST ;
G_DEFINE_AUTOPTR_CLEANUP_FUNC (SeafileDiffEntry, g_object_unref)
VALA_EXTERN SeafileDiffEntry* seafile_diff_entry_new (void);
VALA_EXTERN SeafileDiffEntry* seafile_diff_entry_construct (GType object_type);
VALA_EXTERN const gchar* seafile_diff_entry_get_status (SeafileDiffEntry* self);
VALA_EXTERN void seafile_diff_entry_set_status (SeafileDiffEntry* self,
                                    const gchar* value);
VALA_EXTERN const gchar* seafile_diff_entry_get_name (SeafileDiffEntry* self);
VALA_EXTERN void seafile_diff_entry_set_name (SeafileDiffEntry* self,
                                  const gchar* value);
VALA_EXTERN const gchar* seafile_diff_entry_get_new_name (SeafileDiffEntry* self);
VALA_EXTERN void seafile_diff_entry_set_new_name (SeafileDiffEntry* self,
                                      const gchar* value);
VALA_EXTERN GType seafile_encryption_info_get_type (void) G_GNUC_CONST ;
G_DEFINE_AUTOPTR_CLEANUP_FUNC (SeafileEncryptionInfo, g_object_unref)
VALA_EXTERN SeafileEncryptionInfo* seafile_encryption_info_new (void);
VALA_EXTERN SeafileEncryptionInfo* seafile_encryption_info_construct (GType object_type);
VALA_EXTERN const gchar* seafile_encryption_info_get_repo_id (SeafileEncryptionInfo* self);
VALA_EXTERN void seafile_encryption_info_set_repo_id (SeafileEncryptionInfo* self,
                                          const gchar* value);
VALA_EXTERN const gchar* seafile_encryption_info_get_passwd (SeafileEncryptionInfo* self);
VALA_EXTERN void seafile_encryption_info_set_passwd (SeafileEncryptionInfo* self,
                                         const gchar* value);
VALA_EXTERN gint seafile_encryption_info_get_enc_version (SeafileEncryptionInfo* self);
VALA_EXTERN void seafile_encryption_info_set_enc_version (SeafileEncryptionInfo* self,
                                              gint value);
VALA_EXTERN const gchar* seafile_encryption_info_get_magic (SeafileEncryptionInfo* self);
VALA_EXTERN void seafile_encryption_info_set_magic (SeafileEncryptionInfo* self,
                                        const gchar* value);
VALA_EXTERN const gchar* seafile_encryption_info_get_pwd_hash (SeafileEncryptionInfo* self);
VALA_EXTERN void seafile_encryption_info_set_pwd_hash (SeafileEncryptionInfo* self,
                                           const gchar* value);
VALA_EXTERN const gchar* seafile_encryption_info_get_random_key (SeafileEncryptionInfo* self);
VALA_EXTERN void seafile_encryption_info_set_random_key (SeafileEncryptionInfo* self,
                                             const gchar* value);
VALA_EXTERN const gchar* seafile_encryption_info_get_salt (SeafileEncryptionInfo* self);
VALA_EXTERN void seafile_encryption_info_set_salt (SeafileEncryptionInfo* self,
                                       const gchar* value);
VALA_EXTERN GType seafile_file_sync_error_get_type (void) G_GNUC_CONST ;
G_DEFINE_AUTOPTR_CLEANUP_FUNC (SeafileFileSyncError, g_object_unref)
VALA_EXTERN SeafileFileSyncError* seafile_file_sync_error_new (void);
VALA_EXTERN SeafileFileSyncError* seafile_file_sync_error_construct (GType object_type);
VALA_EXTERN gint seafile_file_sync_error_get_id (SeafileFileSyncError* self);
VALA_EXTERN void seafile_file_sync_error_set_id (SeafileFileSyncError* self,
                                     gint value);
VALA_EXTERN const gchar* seafile_file_sync_error_get_repo_id (SeafileFileSyncError* self);
VALA_EXTERN void seafile_file_sync_error_set_repo_id (SeafileFileSyncError* self,
                                          const gchar* value);
VALA_EXTERN const gchar* seafile_file_sync_error_get_repo_name (SeafileFileSyncError* self);
VALA_EXTERN void seafile_file_sync_error_set_repo_name (SeafileFileSyncError* self,
                                            const gchar* value);
VALA_EXTERN const gchar* seafile_file_sync_error_get_path (SeafileFileSyncError* self);
VALA_EXTERN void seafile_file_sync_error_set_path (SeafileFileSyncError* self,
                                       const gchar* value);
VALA_EXTERN gint seafile_file_sync_error_get_err_id (SeafileFileSyncError* self);
VALA_EXTERN void seafile_file_sync_error_set_err_id (SeafileFileSyncError* self,
                                         gint value);
VALA_EXTERN gint64 seafile_file_sync_error_get_timestamp (SeafileFileSyncError* self);
VALA_EXTERN void seafile_file_sync_error_set_timestamp (SeafileFileSyncError* self,
                                            gint64 value);
VALA_EXTERN GType seafile_task_get_type (void) G_GNUC_CONST ;
G_DEFINE_AUTOPTR_CLEANUP_FUNC (SeafileTask, g_object_unref)
VALA_EXTERN SeafileTask* seafile_task_new (void);
VALA_EXTERN SeafileTask* seafile_task_construct (GType object_type);
VALA_EXTERN const gchar* seafile_task_get_ttype (SeafileTask* self);
VALA_EXTERN void seafile_task_set_ttype (SeafileTask* self,
                             const gchar* value);
VALA_EXTERN const gchar* seafile_task_get_repo_id (SeafileTask* self);
VALA_EXTERN void seafile_task_set_repo_id (SeafileTask* self,
                               const gchar* value);
VALA_EXTERN const gchar* seafile_task_get_state (SeafileTask* self);
VALA_EXTERN void seafile_task_set_state (SeafileTask* self,
                             const gchar* value);
VALA_EXTERN const gchar* seafile_task_get_rt_state (SeafileTask* self);
VALA_EXTERN void seafile_task_set_rt_state (SeafileTask* self,
                                const gchar* value);
VALA_EXTERN gint64 seafile_task_get_block_total (SeafileTask* self);
VALA_EXTERN void seafile_task_set_block_total (SeafileTask* self,
                                   gint64 value);
VALA_EXTERN gint64 seafile_task_get_block_done (SeafileTask* self);
VALA_EXTERN void seafile_task_set_block_done (SeafileTask* self,
                                  gint64 value);
VALA_EXTERN gint seafile_task_get_fs_objects_total (SeafileTask* self);
VALA_EXTERN void seafile_task_set_fs_objects_total (SeafileTask* self,
                                        gint value);
VALA_EXTERN gint seafile_task_get_fs_objects_done (SeafileTask* self);
VALA_EXTERN void seafile_task_set_fs_objects_done (SeafileTask* self,
                                       gint value);
VALA_EXTERN gint seafile_task_get_rate (SeafileTask* self);
VALA_EXTERN void seafile_task_set_rate (SeafileTask* self,
                            gint value);
VALA_EXTERN GType seafile_clone_task_get_type (void) G_GNUC_CONST ;
G_DEFINE_AUTOPTR_CLEANUP_FUNC (SeafileCloneTask, g_object_unref)
VALA_EXTERN SeafileCloneTask* seafile_clone_task_new (void);
VALA_EXTERN SeafileCloneTask* seafile_clone_task_construct (GType object_type);
VALA_EXTERN const gchar* seafile_clone_task_get_state (SeafileCloneTask* self);
VALA_EXTERN void seafile_clone_task_set_state (SeafileCloneTask* self,
                                   const gchar* value);
VALA_EXTERN gint seafile_clone_task_get_error (SeafileCloneTask* self);
VALA_EXTERN void seafile_clone_task_set_error (SeafileCloneTask* self,
                                   gint value);
VALA_EXTERN const gchar* seafile_clone_task_get_repo_id (SeafileCloneTask* self);
VALA_EXTERN void seafile_clone_task_set_repo_id (SeafileCloneTask* self,
                                     const gchar* value);
VALA_EXTERN const gchar* seafile_clone_task_get_repo_name (SeafileCloneTask* self);
VALA_EXTERN void seafile_clone_task_set_repo_name (SeafileCloneTask* self,
                                       const gchar* value);
VALA_EXTERN const gchar* seafile_clone_task_get_worktree (SeafileCloneTask* self);
VALA_EXTERN void seafile_clone_task_set_worktree (SeafileCloneTask* self,
                                      const gchar* value);

G_END_DECLS

#endif
