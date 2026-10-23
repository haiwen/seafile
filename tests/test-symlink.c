/* Offline integration tests: use the production chunker, object store, index,
 * content comparison and checkout, with disk blocks in place of HTTP. */
#include "common.h"
#include "seafile-session.h"
#include "fs-mgr.h"
#include "block-mgr.h"
#include "symlink.h"
#include "vc-utils.h"
#include "set-perm.h"
#include "seafile-config.h"

SeafileSession *seaf;
static const char *repo_id = "11111111-1111-4111-8111-111111111111";
static char *test_dir;

static int
read_block (const char *repo, const char *id, int fd, SeafileCrypt *crypt,
            CheckoutBlockAux *aux)
{
    BlockHandle *handle = seaf_block_manager_open_block (seaf->block_mgr, repo, 1, id, BLOCK_READ);
    g_assert_nonnull (handle);
    BlockMetadata *meta = seaf_block_manager_stat_block_by_handle (seaf->block_mgr, handle);
    g_assert_nonnull (meta);
    char *buf = g_malloc (meta->size);
    g_assert_cmpint (seaf_block_manager_read_block (seaf->block_mgr, handle, buf, meta->size), ==, meta->size);
    int len = meta->size;
    if (crypt) {
        char *plain;
        g_assert_cmpint (seafile_decrypt (&plain, &len, buf, meta->size, crypt), ==, 0);
        g_free (buf);
        buf = plain;
    }
    g_assert_cmpint (writen (fd, buf, len), ==, len);
    g_free (buf);
    g_free (meta);
    seaf_block_manager_close_block (seaf->block_mgr, handle);
    seaf_block_manager_block_handle_free (seaf->block_mgr, handle);
    return 0;
}

static void
index_test_path (const char *path, SeafileCrypt *crypt, unsigned char sha1[20])
{
    gint64 size;
    g_assert_cmpint (seaf_fs_manager_index_blocks (seaf->fs_mgr, repo_id, 1, path,
                        sha1, &size, crypt, TRUE, TRUE, NULL), ==, 0);
    SeafStat st;
    g_assert_cmpint (seaf_worktree_stat (path, &st), ==, 0);
    g_assert_cmpint (size, ==, st.st_size);
}

static int index_calls;
static int
index_cb (const char *repo, int version, const char *path, unsigned char sha1[],
          SeafileCrypt *crypt, gboolean write_data, gboolean *record_error)
{
    ++index_calls;
    index_test_path (path, crypt, sha1);
    return 0;
}

static void
checkout (const char *path, const unsigned char sha1[20], SeafileCrypt *crypt,
          gboolean conflict)
{
    char id[41];
    rawdata_to_hex (sha1, id, 20);
    gboolean conflicted;
    int error;
    FileCheckoutData data = {0};
    data.repo_id = repo_id;
    data.version = 1;
    data.file_id = id;
    data.file_path = path;
    data.in_repo_path = "link";
    data.mode = S_IFREG | 0644;
    data.mtime = 1234567890;
    data.email = "real-user@example.org";
    data.crypt = crypt;
    data.force_conflict = conflict;
    data.conflicted = &conflicted;
    g_assert_cmpint (seaf_fs_manager_checkout_file (seaf->fs_mgr, &data, &error,
                                                   read_block, NULL), ==, 0);
    g_assert_cmpint (conflicted, ==, conflict);
}

static void
assert_target (const char *path, const char *target)
{
    char buf[SEAF_SYMLINK_TARGET_MAX + 1];
    ssize_t n = readlink (path, buf, sizeof(buf));
    g_assert_cmpint (n, ==, strlen(target));
    g_assert_cmpmem (buf, n, target, strlen(target));
}

static void
roundtrip (gconstpointer user_data)
{
    const char *target = user_data;
    char *source = g_build_filename (test_dir, "source", NULL);
    char *legacy = g_build_filename (test_dir, "legacy", NULL);
    char *materialized = g_build_filename (test_dir, "materialized", NULL);
    g_assert_cmpint (symlink (target, source), ==, 0);
    for (int encrypted = 0; encrypted < 2; ++encrypted) {
        unsigned char key[32] = {1}, iv[16] = {2};
        SeafileCrypt *crypt = encrypted ? seafile_crypt_new (2, key, iv) : NULL;
        unsigned char original[20], reindexed[20];
        seaf->preserve_symlinks = TRUE;
        index_test_path (source, crypt, original);
        if (!encrypted && strcmp (target, "../missing") == 0) {
            /* Also indexed by a separately built version without symlink preservation. */
            char id[41];
            rawdata_to_hex (original, id, 20);
            g_assert_cmpstr (id, ==, "fc000fedef226710fa10809c49857a5e5caf52ca");
        }

        /* The ordinary-file path used by clients without link support. */
        seaf->preserve_symlinks = FALSE;
        checkout (legacy, original, crypt, FALSE);
        SeafStat st;
        g_assert_cmpint (lstat (legacy, &st), ==, 0);
        g_assert_true (S_ISREG(st.st_mode));
        g_assert_cmpint (st.st_size, ==, SEAF_SYMLINK_HEADER_SIZE + SEAF_SYMLINK_ENCODED_SIZE(strlen(target)));
        index_test_path (legacy, crypt, reindexed);
        g_assert_cmpmem (original, 20, reindexed, 20);

        /* A second automatic scan must neither index nor change the modifier. */
        struct index_state istate = {0};
        char *index_file = g_build_filename (test_dir, "index", NULL);
        g_assert_cmpint (read_index_from (&istate, index_file, 1), >=, 0);
        gboolean added;
        index_calls = 0;
        for (int scan = 0; scan < 2; ++scan) {
            g_assert_cmpint (add_to_index (repo_id, 1, &istate, "link", legacy, &st,
                                0, crypt, index_cb, "real-user@example.org", &added, NULL), ==, 0);
            g_assert_cmpint (added, ==, scan == 0);
        }
        g_assert_cmpint (index_calls, ==, 1);
        struct cache_entry *ce = index_name_exists (&istate, "link", 4, 0);
        g_assert_cmpstr (ce->modifier, ==, "real-user@example.org");
        g_assert_cmpint (update_index (&istate, index_file), ==, 0);
        discard_index (&istate);
        memset (&istate, 0, sizeof(istate));
        g_assert_cmpint (read_index_from (&istate, index_file, 1), >=, 0);
        ce = index_name_exists (&istate, "link", 4, 0);
        g_assert_nonnull (ce);
        g_assert_cmpstr (ce->modifier, ==, "real-user@example.org");
        g_assert_cmpint (add_to_index (repo_id, 1, &istate, "link", legacy, &st,
                            0, crypt, index_cb, "other-user@example.org", &added, NULL), ==, 0);
        g_assert_false (added);
        g_assert_cmpstr (ce->modifier, ==, "real-user@example.org");
        discard_index (&istate);
        g_unlink (index_file);
        g_free (index_file);

        seaf->preserve_symlinks = TRUE;
        checkout (materialized, reindexed, crypt, FALSE);
        assert_target (materialized, target);
        g_assert_cmpint (seaf_worktree_stat (materialized, &st), ==, 0);
        g_assert_cmpint (st.st_mtime, ==, 1234567890);
        g_assert_cmpint (compare_file_content (materialized, &st, original, crypt, 1), ==, 0);
        index_test_path (materialized, crypt, reindexed);
        g_assert_cmpmem (original, 20, reindexed, 20);
        g_assert_cmpint (delete_path (test_dir, "materialized", S_IFREG | 0644, st.st_mtime), ==, 0);
        g_assert_false (seaf_symlink_exists (materialized));
        g_unlink (legacy);
        g_free (crypt);
    }
    g_unlink (source);
    g_free (source);
    g_free (legacy);
    g_free (materialized);
}

static void
test_invalid_records (void)
{
    char *path = g_build_filename (test_dir, "invalid", NULL);
    const char *invalid[] = {"", "ordinary file", SEAF_SYMLINK_MAGIC,
        SEAF_SYMLINK_MAGIC "bad\0target", "\0SEAFILE-SYMLINK:unknown:2\ntarget",
        SEAF_SYMLINK_MAGIC "YR==", SEAF_SYMLINK_MAGIC "YQ",
        SEAF_SYMLINK_MAGIC "AA==", SEAF_SYMLINK_MAGIC "YQ==\n"};
    gsize sizes[] = {0, 13, SEAF_SYMLINK_HEADER_SIZE,
        SEAF_SYMLINK_HEADER_SIZE + 10, sizeof("\0SEAFILE-SYMLINK:unknown:2\ntarget") - 1,
        SEAF_SYMLINK_HEADER_SIZE + 4, SEAF_SYMLINK_HEADER_SIZE + 2,
        SEAF_SYMLINK_HEADER_SIZE + 4, SEAF_SYMLINK_HEADER_SIZE + 5};
    for (guint i = 0; i < G_N_ELEMENTS(invalid); ++i) {
        g_assert_true (g_file_set_contents (path, invalid[i], sizes[i], NULL));
        g_assert_cmpint (seaf_symlink_materialize (path), ==, 0);
        char *contents; gsize len;
        g_assert_true (g_file_get_contents (path, &contents, &len, NULL));
        g_assert_cmpmem (contents, len, invalid[i], sizes[i]);
        g_free (contents);
    }
    char large[SEAF_SYMLINK_HEADER_SIZE + SEAF_SYMLINK_ENCODED_SIZE(SEAF_SYMLINK_TARGET_MAX) + 1];
    memset (large, 'x', sizeof(large));
    memcpy (large, SEAF_SYMLINK_MAGIC, SEAF_SYMLINK_HEADER_SIZE);
    g_assert_true (g_file_set_contents (path, large, sizeof(large), NULL));
    g_assert_cmpint (seaf_symlink_materialize (path), ==, 0);
    g_unlink (path);
    g_free (path);
}

static void
test_target_untouched (void)
{
    char *target = g_build_filename (test_dir, "target", NULL);
    char *link = g_build_filename (test_dir, "link", NULL);
    char *temp = g_strconcat (link, "~", NULL);
    g_assert_true (g_file_set_contents (target, "precious", -1, NULL));
    g_assert_cmpint (seaf_set_file_time (target, 1000000000), ==, 0);
    g_assert_cmpint (chmod (target, 0600), ==, 0);
    g_assert_cmpint (symlink (target, link), ==, 0);
    unsigned char sha1[20];
    seaf->preserve_symlinks = TRUE;
    index_test_path (link, NULL, sha1);
    /* Restarting a download must not truncate through a leftover temp link. */
    g_assert_cmpint (symlink (target, temp), ==, 0);
    checkout (link, sha1, NULL, FALSE);
    g_assert_cmpint (seaf_set_path_permission (link, SEAF_PATH_PERM_RO, FALSE), ==, 0);
    struct stat st;
    g_assert_cmpint (stat (target, &st), ==, 0);
    g_assert_cmpint (st.st_mtime, ==, 1000000000);
    g_assert_cmpint (st.st_mode & 0777, ==, 0600);
    char *contents;
    g_assert_true (g_file_get_contents (target, &contents, NULL, NULL));
    g_assert_cmpstr (contents, ==, "precious");
    g_free (contents);
    g_unlink (link); g_unlink (target);
    g_free (temp); g_free (link); g_free (target);
}

static void
test_dangling_conflict (void)
{
    char *source = g_build_filename (test_dir, "source", NULL);
    char *dest = g_build_filename (test_dir, "conflict", NULL);
    g_assert_cmpint (symlink ("new-missing", source), ==, 0);
    g_assert_cmpint (symlink ("old-missing", dest), ==, 0);
    seaf->preserve_symlinks = TRUE;
    unsigned char sha1[20];
    index_test_path (source, NULL, sha1);
    checkout (dest, sha1, NULL, TRUE);
    assert_target (dest, "new-missing");
    GDir *dir = g_dir_open (test_dir, 0, NULL);
    const char *name;
    gboolean found = FALSE;
    while ((name = g_dir_read_name (dir))) {
        if (g_str_has_prefix (name, "conflict") && strcmp(name, "conflict") != 0) {
            char *path = g_build_filename (test_dir, name, NULL);
            assert_target (path, "old-missing");
            found = TRUE;
            g_unlink (path); g_free (path);
        }
    }
    g_dir_close (dir);
    g_assert_true (found);
    g_unlink (source); g_unlink (dest);
    g_free (source); g_free (dest);
}

static void
test_directory_link (void)
{
    char *link = g_build_filename (test_dir, "loop", NULL);
    g_assert_cmpint (symlink (".", link), ==, 0);
    seaf->preserve_symlinks = TRUE;
    SeafStat st;
    g_assert_cmpint (seaf_worktree_stat (link, &st), ==, 0);
    g_assert_true (S_ISREG(st.st_mode));
    g_assert_true (seaf_worktree_has_symlink_parent (test_dir, "loop/escape"));
    g_assert_false (seaf_worktree_has_symlink_parent (test_dir, "loop"));
    g_assert_false (seaf_worktree_has_symlink_parent (test_dir, ""));
    g_assert_cmpint (delete_path (test_dir, "loop/escape", S_IFREG | 0644, 0), ==, -1);
    g_test_expect_message (NULL, G_LOG_LEVEL_WARNING, "*Failed to create directory*");
    g_assert_null (build_checkout_path (test_dir, "loop/escape", 11));
    g_test_assert_expected_messages ();
    seaf->preserve_symlinks = FALSE;
    g_assert_cmpint (seaf_worktree_stat (link, &st), ==, 0);
    g_assert_true (S_ISDIR(st.st_mode));
    g_unlink (link); g_free (link);
}

static void
test_same_timestamp_retarget (void)
{
    char *path = g_build_filename (test_dir, "retarget", NULL);
    char *index_file = g_build_filename (test_dir, "index", NULL);
    struct index_state istate = {0};
    g_assert_cmpint (read_index_from (&istate, index_file, 1), >=, 0);
    seaf->preserve_symlinks = TRUE;
    unsigned char original[20];
    for (int i = 0; i < 3; ++i) {
        if (i != 2) {
            g_assert_cmpint (symlink (i ? "two" : "one", path), ==, 0);
            g_assert_cmpint (seaf_symlink_set_time (path, 1234567890), ==, 0);
        }
        SeafStat st;
        g_assert_cmpint (seaf_worktree_stat (path, &st), ==, 0);
        gboolean added;
        g_assert_cmpint (add_to_index (repo_id, 1, &istate, "retarget", path, &st,
                        ADD_CACHE_CHECK_CONTENT, NULL, index_cb, "user", &added, NULL), ==, 0);
        g_assert_cmpint (added, ==, i != 2);
        struct cache_entry *ce = index_name_exists (&istate, "retarget", 8, 0);
        if (i == 0) {
            memcpy (original, ce->sha1, 20);
            g_unlink (path);
        } else {
            g_assert_cmpint (memcmp (original, ce->sha1, 20), !=, 0);
        }
    }
    discard_index (&istate);
    g_unlink (path);
    g_free (path); g_free (index_file);
}

static void
test_ignore_file (void)
{
    char *source = g_build_filename (test_dir, "source", NULL);
    char *ignore = g_build_filename (test_dir, "seafile-ignore.txt", NULL);
    g_assert_cmpint (symlink ("\n*", source), ==, 0);
    unsigned char sha1[20];
    seaf->preserve_symlinks = TRUE;
    index_test_path (source, NULL, sha1);
    seaf->preserve_symlinks = FALSE;
    checkout (ignore, sha1, NULL, FALSE);
    g_assert_null (seaf_repo_load_ignore_files (test_dir));
    seaf->preserve_symlinks = TRUE;
    checkout (ignore, sha1, NULL, FALSE);
    assert_target (ignore, "\n*");
    g_assert_null (seaf_repo_load_ignore_files (test_dir));
    g_unlink (source); g_unlink (ignore);
    g_free (source); g_free (ignore);
}

static void
test_directory_reconstruction (void)
{
    char *source = g_build_filename (test_dir, "source", NULL);
    g_assert_cmpint (symlink ("../missing", source), ==, 0);
    seaf->preserve_symlinks = TRUE;
    unsigned char sha1[20]; char id[41];
    index_test_path (source, NULL, sha1);
    rawdata_to_hex (sha1, id, 20);
    SeafStat st;
    g_assert_cmpint (seaf_worktree_stat (source, &st), ==, 0);
    SeafDirent *entry = seaf_dirent_new (1, id, S_IFREG | 0644, "link",
                                        st.st_mtime, "real-user@example.org", st.st_size);
    SeafDir *dir = seaf_dir_new (NULL, g_list_append (NULL, entry), 1);
    int size;
    void *data = seaf_dir_to_data (dir, &size);
    SeafDir *parsed = seaf_dir_from_data (dir->dir_id, data, size, TRUE);
    g_assert_nonnull (parsed);
    g_free (data);
    /* Legacy parsing followed by a sibling change and directory rewrite. */
    SeafDirent *sibling = seaf_dirent_new (1, EMPTY_SHA1, S_IFREG | 0644,
                                         "unrelated", st.st_mtime, "other-user", 0);
    parsed->entries = g_list_prepend (parsed->entries, sibling);
    data = seaf_dir_to_data (parsed, &size);
    SeafDir *rewritten = seaf_dir_from_data (parsed->dir_id, data, size, TRUE);
    g_assert_nonnull (rewritten);
    gboolean found = FALSE;
    for (GList *p = rewritten->entries; p; p = p->next) {
        SeafDirent *e = p->data;
        if (strcmp (e->name, "link") == 0) {
            g_assert_cmpstr (e->id, ==, id);
            g_assert_cmpstr (e->modifier, ==, "real-user@example.org");
            g_assert_cmpint (e->mode, ==, S_IFREG | 0644);
            g_assert_cmpint (e->size, ==, st.st_size);
            found = TRUE;
        }
    }
    g_assert_true (found);
    g_free (data);
    seaf_dir_free (rewritten); seaf_dir_free (parsed); seaf_dir_free (dir);
    g_unlink (source); g_free (source);
}

static void
remove_test_dir (const char *path)
{
    struct stat st;
    g_assert_cmpint (lstat (path, &st), ==, 0);
    if (S_ISDIR(st.st_mode)) {
        GDir *dir = g_dir_open (path, 0, NULL);
        g_assert_nonnull (dir);
        const char *name;
        while ((name = g_dir_read_name (dir))) {
            char *child = g_build_filename (path, name, NULL);
            remove_test_dir (child);
            g_free (child);
        }
        g_dir_close (dir);
        g_assert_cmpint (g_rmdir (path), ==, 0);
    } else {
        g_assert_cmpint (g_unlink (path), ==, 0);
    }
}

static void
test_settings_transition (void)
{
    SeafileSession session = {0};
    g_assert_cmpint (sqlite3_open (":memory:", &session.config_db), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_exec (session.config_db,
        "CREATE TABLE Config (key TEXT PRIMARY KEY, value TEXT)", NULL, NULL, NULL), ==, SQLITE_OK);

    /* Ignore-only changes retain their immediate effect. */
    g_assert_cmpint (seafile_session_config_set_string (&session, KEY_IGNORE_SYMLINKS, "true"), ==, 0);
    g_assert_true (session.ignore_symlinks);

    /* The applet saves both options, but current scans must still ignore links
     * until the daemon restarts with preservation enabled. */
    g_assert_cmpint (seafile_session_config_set_string (&session, KEY_PRESERVE_SYMLINKS, "true"), ==, 0);
    g_assert_cmpint (seafile_session_config_set_string (&session, KEY_IGNORE_SYMLINKS, "false"), ==, 0);
    g_assert_false (session.preserve_symlinks);
    g_assert_true (session.ignore_symlinks);
    g_assert_true (seafile_session_config_get_bool (&session, KEY_PRESERVE_SYMLINKS));
    g_assert_false (seafile_session_config_get_bool (&session, KEY_IGNORE_SYMLINKS));

    /* Simulate loading the persisted options on restart, then switch back. */
    session.preserve_symlinks = seafile_session_config_get_bool (&session, KEY_PRESERVE_SYMLINKS);
    session.ignore_symlinks = seafile_session_config_get_bool (&session, KEY_IGNORE_SYMLINKS);
    g_assert_cmpint (seafile_session_config_set_string (&session, KEY_PRESERVE_SYMLINKS, "false"), ==, 0);
    g_assert_cmpint (seafile_session_config_set_string (&session, KEY_IGNORE_SYMLINKS, "true"), ==, 0);
    g_assert_true (session.preserve_symlinks);
    g_assert_false (session.ignore_symlinks);

    /* Cancel a pending change before restart. */
    g_assert_cmpint (seafile_session_config_set_string (&session, KEY_PRESERVE_SYMLINKS, "true"), ==, 0);
    g_assert_cmpint (seafile_session_config_set_string (&session, KEY_IGNORE_SYMLINKS, "false"), ==, 0);
    g_assert_true (session.preserve_symlinks);
    g_assert_false (session.ignore_symlinks);
    sqlite3_close (session.config_db);
}

int
main (int argc, char **argv)
{
    g_test_init (&argc, &argv, NULL);
    static SeafileSession session;
    seaf = &session;
    test_dir = g_dir_make_tmp ("seafile-symlink-test-XXXXXX", NULL);
    g_assert_nonnull (test_dir);
    session.seaf_dir = test_dir;
    session.tmp_file_dir = g_build_filename (test_dir, "tmp", NULL);
    session.fs_mgr = seaf_fs_manager_new (&session, test_dir);
    session.block_mgr = seaf_block_manager_new (&session, test_dir);
    g_assert_nonnull (session.fs_mgr);
    g_assert_nonnull (session.block_mgr);
    cdc_init ();
    g_test_add_data_func ("/symlink/relative", "../missing", roundtrip);
    g_test_add_data_func ("/symlink/absolute", "/missing/seafile-symlink-target", roundtrip);
    g_test_add_data_func ("/symlink/raw-bytes", "../space newline\n\xff", roundtrip);
    g_test_add_data_func ("/symlink/self", "source", roundtrip);
    g_test_add_data_func ("/symlink/directory-target", ".", roundtrip);
    g_test_add_func ("/symlink/invalid-records", test_invalid_records);
    g_test_add_func ("/symlink/target-untouched", test_target_untouched);
    g_test_add_func ("/symlink/dangling-conflict", test_dangling_conflict);
    g_test_add_func ("/symlink/directory", test_directory_link);
    g_test_add_func ("/symlink/same-timestamp-retarget", test_same_timestamp_retarget);
    g_test_add_func ("/symlink/ignore-file", test_ignore_file);
    g_test_add_func ("/symlink/directory-reconstruction", test_directory_reconstruction);
    g_test_add_func ("/symlink/settings-transition", test_settings_transition);
    char *long_target = g_strnfill (SEAF_SYMLINK_TARGET_MAX, 'x');
    g_test_add_data_func ("/symlink/maximum-target", long_target, roundtrip);
    int ret = g_test_run ();
    g_free (long_target);
    remove_test_dir (test_dir);
    g_free (session.tmp_file_dir);
    g_free (test_dir);
    return ret;
}
