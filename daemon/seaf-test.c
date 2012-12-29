/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <stdio.h>
#include <sys/types.h>
#ifndef WIN32
#include <sys/wait.h>
#else
#include <Windows.h>
#define sleep(t) Sleep(t*1000)
#define WEXITSTATUS(status) (((status) & 0xff00) >> 8)
#endif

#include <sys/stat.h>

#include <ccnet.h>

#include "seafile-session.h"
#include "branch-mgr.h"
#include "commit-mgr.h"
#include "fs-mgr.h"
#include "index/index.h"
#include "seafile-rpc.h"
#include "vc-utils.h"


CcnetClient *client;
SeafileSession *seaf;

#define TEST_DIR        "../tests/basic/"
#define CCNET_DIR       TEST_DIR "conf1/"
#define SEAF_DIR        CCNET_DIR "seafile-data/"
#define WORKTREE_DIR    TEST_DIR "worktree/wt1/"

static void setup()
{
    client = ccnet_client_new ();
    if ( ccnet_client_load_confdir(client, CCNET_DIR) < 0 ) {
        fprintf (stderr, "Read config dir error\n");
        exit(1);
    }

    event_init ();

    if (g_access (TEST_DIR "worktree", F_OK) != 0 &&
        g_mkdir (TEST_DIR "worktree", 0777) < 0) {
        fprintf (stderr, "Failed to create worktree.\n");
        exit (1);
    }

    seaf = seafile_session_new (SEAF_DIR, 
                                WORKTREE_DIR,
                                client);
    if (!seaf) {
        fprintf (stderr, "Failed to create seafile session.\n");
        exit (1);
    }
    seafile_session_prepare (seaf);
}

static void teardown ()
{
#ifndef WIN32
    int ret = system ("cd "TEST_DIR"; ./clean.sh > /dev/null 2>&1");
#else
    int ret = system ("cd "TEST_DIR"; ./clean.sh");
#endif
    if (ret < 0 || WEXITSTATUS(ret) != 0) {
        fprintf (stderr, "Failed to copy data\n");
        exit (1);
    }
}

static SeafRepo* create_repo (const char *repo_name)
{
    SeafRepo *repo;
    const char *repo_id;
    GError *error = NULL;
    char *wt_path;
    char cmd[1024];

    wt_path = g_build_filename (WORKTREE_DIR, repo_name, NULL);
    snprintf (cmd, 1024, "cp -R %s/data %s", TEST_DIR, wt_path);
    int ret = system (cmd);
    if (ret < 0 || WEXITSTATUS(ret) != 0) {
        fprintf (stderr, "Failed to copy data\n");
        exit (1);
    }

    /* create a non encrypted repo */
    repo_id = seafile_create_repo (repo_name, "test",
                "example@abc.com", NULL, &error);
    if (!repo_id) {
        fprintf (stderr, "Failed to create repo: %s.\n", error->message);
        exit (1);
    }
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
   
    g_free (wt_path);
    return repo;
}

static const char* first_commit (SeafRepo *repo)
{
    GError *error = NULL;
    const char *commit_id;

    printf ("\n*** first commit.\n");

    if (seafile_add (repo->id, "", &error) < 0) {
        fprintf (stderr, "Failed to add: %s.\n", error->message);
        return NULL;
    }

    commit_id = seafile_commit (repo->id, "first commit", &error);
    if (commit_id == NULL) {
        fprintf (stderr, "Failed to commit: %s\n", error->message);
        return NULL;
    }

    return commit_id;
}

static int print_index (SeafRepo *repo)
{
    char *index_file;
    struct index_state istate;

    index_file = g_build_path (PATH_SEPERATOR, SEAF_DIR, "index", repo->id, NULL);

    memset (&istate, 0, sizeof(istate));
    if (read_index_from (&istate, index_file) < 0) {
        fprintf (stderr, "Corrupt index file %s\n", index_file);
        return -1;
    }

    printf ("Index timestamp: %d\n", istate.timestamp.sec);

    int i;
    struct cache_entry *ce;
    char id[41];
    printf ("Totally %u entries in index.\n", istate.cache_nr);
    for (i = 0; i < istate.cache_nr; ++i) {
        ce = istate.cache[i];
        rawdata_to_hex (ce->sha1, id, 20);
        printf ("%s\t%s\t%o\t%d\t%d\n", ce->name, id, ce->ce_mode, 
                ce->ce_ctime.sec, ce->ce_mtime.sec);
    }

    return 0;
}

static int check_seafile (const char *id)
{
    Seafile *seafile;

    seafile = seaf_fs_manager_get_seafile (seaf->fs_mgr, id);
    if (!seafile) {
        fprintf (stderr, "Failed to read seafile %s\n", id);
        return -1;
    }

    seafile_unref (seafile);
    return 0;
}

static int traverse_dir (const char *id)
{
    SeafDir *dir;
    GList *p;
    SeafDirent *seaf_dent;

    dir = seaf_fs_manager_get_seafdir (seaf->fs_mgr, id);
    if (!dir) {
        fprintf (stderr, "Failed to read dir %s\n", id);
        return -1;
    }

    for (p = dir->entries; p; p = p->next) {
        seaf_dent = (SeafDirent *)p->data;

        if (S_ISREG(seaf_dent->mode)) {
            printf ("check file %s\n", seaf_dent->name);
            return check_seafile (seaf_dent->id);
        } else if (S_ISDIR(seaf_dent->mode)) {
            printf ("check directory %s\n", seaf_dent->name);
            return traverse_dir (seaf_dent->id);
        }
    }

    seaf_dir_free (dir);
    return 0;
}

static int test_commit()
{
    SeafRepo *repo;
    SeafCommit *commit;
    const char *commit_id;

    printf ("\n=== test commit\n");

    repo = create_repo ("test-commit");

    commit_id = first_commit (repo);

    printf ("*** print index\n");
    if (print_index (repo) < 0)
        return -1;

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr, commit_id);
    if (!commit) {
        fprintf (stderr, "Failed to get commit\n");
        return -1;
    }

    if (traverse_dir (commit->root_id) < 0)
        return -1;

    /* status */
    char *status = seaf_repo_status (repo);
    printf ("Status\n%s", status);
    g_assert (strcmp(status, "") == 0);
    g_free (status);

    seaf_commit_unref (commit);

    printf ("\n=== test commit succeeded.\n");
    return 0;
}

static int test_get_fs_size()
{
    gint64 size;
    const char *commit_id;
    SeafCommit *commit;
    SeafRepo *repo;

    printf ("\n=== test get fs size\n");

    repo = create_repo ("get_fs_size");

    commit_id = first_commit (repo);

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr, commit_id);
    if (!commit) {
        fprintf (stderr, "Failed to get commit\n");
        return -1;
    }

    size = seaf_fs_manager_get_fs_size (seaf->fs_mgr, commit->root_id);
    printf ("size is %"G_GINT64_FORMAT"\n", size);
    seaf_commit_unref (commit);

    printf ("\n=== get fs size succeeded.\n");

    return 0;
}

static int
check_file_content (const char *file, const char *content, int clen)
{
    int fd = g_open (file, O_RDONLY | O_BINARY, 0);
    if (fd < 0) {
        fprintf (stderr, "Bug: %s should exist\n", file);
        return -1;
    }
    char buf[64];
    memset(buf, 0, sizeof(buf));
    if (read (fd, buf, sizeof(buf)) < 0) {
        fprintf (stderr, "Failed to read %s: %s.\n", file, strerror(errno));
        close (fd);
        return -1;
    }
    if (memcmp (buf, content, clen) != 0) {
        fprintf (stderr, "Bug: content of %s is incorrect.\n", file);
        close (fd);
        return -1;
    }

    close (fd);
    return 0;
}

static int
check_dir (const char *path)
{
    SeafStat st;
    if (g_stat (path, &st) < 0) {
        fprintf (stderr, "Bug: %s should exist.\n", path);
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        fprintf (stderr, "Bug: %s shoudl be directory.\n", path);
        return -1;
    }

    return 0;
}


static int
test_successful_merge ()
{
    SeafRepo *repo;
    char *head, *remote;
    char *file_a, *file_b, *file_c, *file_d;
    FILE *fp_a, *fp_c, *fp_d;
    GError *error = NULL;

    printf ("\n=== test successful merge\n\n");

    repo = create_repo ("successful-merge");

    first_commit (repo);

    sleep (2);

    printf ("*** creating branch \"test\"\n");
    /* create branch "test". */
    if (seafile_branch_add (repo->id, "test", NULL, &error) < 0) {
        fprintf (stderr, "Failed to create branch: %s.\n", error->message);
        return -1;
    }

    /* create a new commit on branch "local". */

    file_a = g_build_filename (repo->worktree, "test-a", NULL);
    file_b = g_build_filename (repo->worktree, "golden-gate.jpg", NULL);
    file_c = g_build_filename (repo->worktree, "new", NULL);
    file_d = g_build_filename (repo->worktree, "c/test-c", NULL);

    /* modify an existing file. */
    fp_a = g_fopen (file_a, "wb");
    if (!fp_a) {
        fprintf (stderr, "Failed to open %s: %s\n", file_a, strerror(errno));
        return -1;
    }
    fprintf (fp_a, "xyzxyz\nxyzxyz");
    fclose (fp_a);

    /* delete a file. */
    (void) g_unlink (file_b);

    /* modify another file. */
    fp_d = g_fopen (file_d, "wb");
    if (!fp_d) {
        fprintf (stderr, "Failed to open %s: %s\n", file_d, strerror(errno));
        return -1;
    }
    fprintf (fp_d, "the same\n");
    fclose (fp_d);

    sleep (2);

    if (seaf_repo_index_add (repo, "") < 0) {
        fprintf (stderr, "Failed to add on branch local\n");
        return -1;
    }

    printf ("*** creating new commit on local\n");
    head = seaf_repo_index_commit (repo, "merge test 1.", FALSE, NULL, &error);
    if (!head) {
        fprintf (stderr, "Failed to commit on branch test\n");
        return -1;
    }

    printf ("*** checking out branchn test.\n");
    /* switch to branch "test". */
    if (seafile_checkout (repo->id, "test", &error) < 0) {
        fprintf (stderr, "Failed to checkout branch test\n");
        fprintf (stderr, "Checkout error messages:\n%s", error->message);
        return -1;
    }

    sleep (2);

    /* create a new commit on branch "test". */

    /* add a new file. */
    fp_c = g_fopen (file_c, "w+b");
    if (!fp_c) {
        fprintf (stderr, "Failed to open %s: %s\n", file_c, strerror(errno));
        return -1;
    }
    fprintf (fp_c, "abcabc\nabcabc");
    fclose (fp_c);

    /* modify another file.
     * The content is the same as "local".
     */
    fp_d = g_fopen (file_d, "wb");
    if (!fp_d) {
        fprintf (stderr, "Failed to open %s: %s\n", file_d, strerror(errno));
        return -1;
    }
    fprintf (fp_d, "the same\n");
    fclose (fp_d);

    sleep (2);

    if (seaf_repo_index_add (repo, "") < 0) {
        fprintf (stderr, "Failed to add on branch test\n");
        return -1;
    }

    printf ("*** creating new commit on branch test.\n");
    remote = seaf_repo_index_commit (repo, "merge test 2.", FALSE, NULL, &error);
    if (!remote) {
        fprintf (stderr, "Failed to commit on branch test\n");
        return -1;
    }

    printf ("*** checking out branch local.\n");
    /* switch back to branch "local". */
    if (seafile_checkout (repo->id, "local", &error) < 0) {
        fprintf (stderr, "Failed to checkout branch local\n");
        fprintf (stderr, "Checkout error messages:\n%s", error->message);
        return -1;
    }

    sleep (2);

    printf ("*** merging test to local.\n");
    /* merge branch "test". */
    if (seafile_merge (repo->id, "test", &error) < 0) {
        fprintf (stderr, "Failed to merge branch test\n");
        fprintf (stderr, "Merge error messages:\n%s", error->message);
        return -1;
    }

    printf ("*** check merge results.\n");

    if (check_file_content (file_a, "xyzxyz\nxyzxyz", 13) < 0) {
        return -1;
    }

    if (g_access (file_b, F_OK) == 0) {
        fprintf (stderr, "Bug in merge: %s should not exist.\n", file_b);
        return -1;
    }

    if (g_access (file_c, F_OK) != 0) {
        fprintf (stderr, "Bug in merge: %s should exist.\n", file_b);
        return -1;
    }

    if (check_file_content (file_d, "the same", 8) < 0) {
        return -1;
    }

    /* list commits */
    seafile_get_commit_list (repo->id, 0, -1, NULL);
    seafile_get_commit_list (repo->id, 0, -1, NULL);

    printf ("\n=== Merge succeeded.\n\n");
    return 0;
}

static int
test_merge_conflicts ()
{
    SeafRepo *repo;
    char *head, *remote;
    char *file_a, *file_b, *file_bb, *file_c, *file_d, *file_e, *file_f;
    FILE *fp_a, *fp_b, *fp_c, *fp_d;
    GError *error = NULL;
    char cmd[1024];
    int ret;
    char buf[64];

    printf ("\n=== test merge conflicts\n\n");

    repo = create_repo ("merge-conflicts");

    first_commit (repo);

    sleep (2);

    printf ("*** creating branch \"test\"\n");
    /* create branch "test". */
    if (seafile_branch_add (repo->id, "test", NULL, &error) < 0) {
        fprintf (stderr, "Failed to create branch: %s.\n", error->message);
        return -1;
    }

    /* create a new commit on branch "local". */

    file_a = g_build_filename (repo->worktree, "test-a", NULL);
    file_b = g_build_filename (repo->worktree, "test-b", NULL);
    file_bb = g_build_filename (repo->worktree, "test-b/b", NULL);
    file_c = g_build_filename (repo->worktree, "c/test-c", NULL);
    file_d = g_build_filename (repo->worktree, "a", NULL);
    file_e = g_build_filename (repo->worktree, "golden-gate.jpg", NULL);
    file_f = g_build_filename (repo->worktree, "a/stanford-cs.jpg", NULL);

    /* modify an existing file, to test modify/modify conflict. */
    fp_a = g_fopen (file_a, "wb");
    if (!fp_a) {
        fprintf (stderr, "Failed to open %s: %s\n", file_a, strerror(errno));
        return -1;
    }
    fprintf (fp_a, "xyzxyz\nxyzxyz");
    fclose (fp_a);

    /* delete a file and create a directory with the same name,
     * to test d/f conflict.
     */
    g_unlink (file_b);

    if (g_mkdir (file_b, 0777) < 0) {
        fprintf (stderr, "Failed to create %s: %s\n", file_b, strerror(errno));
        return -1;
    }
    fp_b = g_fopen (file_bb, "w+b");
    if (!fp_b) {
        fprintf (stderr, "Failed to open %s: %s\n", file_bb, strerror(errno));
        return -1;
    }
    fprintf (fp_b, "1234\n1234\n");
    fclose (fp_b);

    /* modify another file, to test modify/delete conflict. */
    fp_c = g_fopen (file_c, "wb");
    if (!fp_c) {
        fprintf (stderr, "Failed to open %s: %s\n", file_c, strerror(errno));
        return -1;
    }
    fprintf (fp_c, "something else.\n");
    fclose (fp_c);

    /* delete a directory and create a file with the same name,
     * to test d/f conflict.
     */
    snprintf (cmd, 1024, "rm -r %s", file_d);
    ret = system (cmd);
    if (ret < 0 || WEXITSTATUS(ret) != 0) {
        fprintf (stderr, "Failed to remove %s\n", file_d);
        return -1;
    }
    fp_d = g_fopen (file_d, "w+b");
    if (!fp_d) {
        fprintf (stderr, "Failed to open %s: %s\n", file_d, strerror(errno));
        return -1;
    }
    fprintf (fp_d, "1234\n1234\n");
    fclose (fp_d);

    sleep (2);

    if (seaf_repo_index_add (repo, "") < 0) {
        fprintf (stderr, "Failed to add on branch local\n");
        return -1;
    }

    printf ("*** creating new commit on local\n");
    head = seaf_repo_index_commit (repo, "merge test 1.", FALSE, NULL, &error);
    if (!head) {
        fprintf (stderr, "Failed to commit on branch test\n");
        return -1;
    }

    printf ("*** checking out branch test.\n");
    /* switch to branch "test". */
    if (seafile_checkout (repo->id, "test", &error) < 0) {
        fprintf (stderr, "Failed to checkout branch test\n");
        fprintf (stderr, "Checkout error messages:\n%s", error->message);
        return -1;
    }

    sleep (2);

    /* create a new commit on branch "test". */

    /* modify/modify conflict. */
    fp_a = g_fopen (file_a, "w+b");
    if (!fp_a) {
        fprintf (stderr, "Failed to open %s: %s\n", file_a, strerror(errno));
        return -1;
    }
    fprintf (fp_a, "abcabc\nabcabc");
    fclose (fp_a);

    /* df conflict occurs only when files are changed. */
    fp_b = g_fopen (file_b, "wb");
    if (!fp_b) {
        fprintf (stderr, "Failed to open %s: %s\n", file_b, strerror(errno));
        return -1;
    }
    fprintf (fp_b, "12345678");
    fclose (fp_b);    

    /* modify/delete conflict. */
    g_unlink (file_c);

    /* df conflict occurs only when files are changed. */
    snprintf (cmd, 1024, "cp %s %s", file_e, file_f);
    ret = system (cmd);
    if (ret < 0 || WEXITSTATUS(ret) != 0) {
        fprintf (stderr, "Failed to cp %s to %s\n", file_e, file_f);
        return -1;
    }

    sleep (2);

    if (seaf_repo_index_add (repo, "") < 0) {
        fprintf (stderr, "Failed to add on branch test\n");
        return -1;
    }

    printf ("*** creating new commit on branch test.\n");
    remote = seaf_repo_index_commit (repo, "merge test 2.", FALSE, NULL, &error);
    if (!remote) {
        fprintf (stderr, "Failed to commit on branch test\n");
        return -1;
    }

    printf ("*** checking out branch local.\n");
    /* switch back to branch "local". */
    if (seafile_checkout (repo->id, "local", &error) < 0) {
        fprintf (stderr, "Failed to checkout branch local\n");
        fprintf (stderr, "Checkout error messages:\n%s", error->message);
        return -1;
    }

    sleep (2);

    printf ("*** merging test to local.\n");
    /* merge branch "test". */
    if (seafile_merge (repo->id, "test", &error) == 0) {
        fprintf (stderr, "This merge is supposed to fail!!\n");
        return -1;
    }
    fprintf (stderr, "Merge error messages:\n%s", error->message);

    printf ("*** check merge conflict results.\n");

    if (g_access (file_f, F_OK) != 0) {
        fprintf (stderr, "Bug: %s should exist.\n", file_a);
        return -1;
    }

    if (g_access (file_c, F_OK) != 0) {
        fprintf (stderr, "Bug: %s should exist.\n", file_c);
        return -1;
    }
	time_t t = time(NULL);
	strftime(buf, 64, "--plt_%Y-%m-%d", localtime(&t));

    char *file_a_local = g_strconcat (file_a, buf, NULL);
    char *file_a_test = g_strconcat (file_a, "", NULL);
    if (check_file_content (file_a_local, "xyzxyz\nxyzxyz", 13) < 0)
        return -1;
    if (check_file_content (file_a_test, "abcabc\nabcabc", 13) < 0)
        return -1;

    char *file_d_local = g_strconcat (file_d, buf, NULL);
    if (check_file_content (file_d_local, "1234\n1234\n", 10) < 0)
        return -1;
    if (check_dir (file_d) < 0) {
        return -1;
    }

    char *dir_b_test = g_strconcat (file_b, buf, NULL);
    if (check_file_content (file_b, "12345678", 8) < 0)
        return -1;
    if (check_dir (dir_b_test) < 0) {
        return -1;
    }

    printf ("\n=== Successfully handle merge conflict.\n\n");
    return 0;
}

static int
test_commit_compare ()
{
    SeafRepo *repo;
    const char *commit1, *commit2, *commit3;
    GError *error = NULL;

    printf ("\n=== test commit compare\n\n");

    repo = create_repo ("commit-compare");
    commit1 = first_commit (repo);

    sleep (2);
    printf ("*** creating branch \"test\"\n");
    /* create branch "test". */
    if (seafile_branch_add (repo->id, "test", NULL, &error) < 0) {
        fprintf (stderr, "Failed to create branch: %s.\n", error->message);
        return -1;
    }

    printf ("*** creating new commit on local\n");
    commit2 = seaf_repo_index_commit (repo, "commit compare 1.", FALSE, NULL, &error);
    if (!commit2) {
        fprintf (stderr, "Failed to commit on branch test\n");
        return -1;
    }
     
    printf ("*** checking out branch test.\n");
    /* switch to branch "test". */
    if (seafile_checkout (repo->id, "test", &error) < 0) {
        fprintf (stderr, "Failed to checkout branch test\n");
        fprintf (stderr, "Checkout error messages:\n%s", error->message);
        return -1;
    }

    printf ("*** creating new commit on branch test.\n");
    commit3 = seaf_repo_index_commit (repo, "merge test 2.", FALSE, NULL, &error);
    if (!commit3) {
        fprintf (stderr, "Failed to commit on branch test\n");
        return -1;
    }

    printf ("*** compare commit.\n");
    g_assert (seaf_commit_manager_compare_commit (
                  seaf->commit_mgr, commit1, commit2) == -1);
    g_assert (seaf_commit_manager_compare_commit (
                  seaf->commit_mgr, commit2, commit1) == 1);
    g_assert (seaf_commit_manager_compare_commit (
                  seaf->commit_mgr, commit2, commit3) == 0);

    return 0;
}

static int
test_block_manager ()
{
    SeafBlockManager *mgr = seaf->block_mgr;
    char *block_id = "c882e263e9d02c63ca6b61c68508761cbc74c358";
    char wr_buf[1024], rd_buf[1024];
    BlockHandle *handle;
    BlockMetadata *md;
    int n;

    printf ("\n=== Test block manager\n\n");

    memset (wr_buf, 1, sizeof(wr_buf));

    handle = seaf_block_manager_open_block (mgr, block_id, BLOCK_WRITE);
    g_assert (handle != NULL);

    n = seaf_block_manager_write_block (mgr, handle, wr_buf, sizeof(wr_buf));
    g_assert (n == sizeof(wr_buf));

    md = seaf_block_manager_stat_block_by_handle (mgr, handle);
    g_assert (md->size == sizeof(wr_buf));
    g_free (md);

    g_assert (seaf_block_manager_close_block(mgr, handle) == 0);
    g_assert (seaf_block_manager_commit_block(mgr, handle) == 0);

    seaf_block_manager_block_handle_free (mgr, handle);

    handle = seaf_block_manager_open_block (mgr, block_id, BLOCK_READ);
    g_assert (handle != NULL);

    n = seaf_block_manager_read_block (mgr, handle, rd_buf, sizeof(rd_buf));
    g_assert (n == sizeof(rd_buf));

    md = seaf_block_manager_stat_block_by_handle (mgr, handle);
    g_assert (md->size == sizeof(wr_buf));
    g_free (md);

    g_assert (seaf_block_manager_close_block(mgr, handle) == 0);
    seaf_block_manager_block_handle_free (mgr, handle);


    g_assert (memcmp (wr_buf, rd_buf, sizeof(wr_buf)) == 0);

    md = seaf_block_manager_stat_block (mgr, block_id);

    g_assert (strcmp (md->id, block_id) == 0);
    g_assert (md->size == sizeof(wr_buf));

    g_free (md);
    return 0;
}

typedef int (*TestFunc) (void);

struct TestEntry {
    char        *test;
    TestFunc    func;
};

static struct TestEntry test_table[] = {
    { "commit",             test_commit },
    { "get_fs_size",        test_get_fs_size },
    { "merge",              test_successful_merge },
    /* { "merge_conflicts",    test_merge_conflicts }, */
    { "commit_compare",     test_commit_compare },
    { "block_manager",      test_block_manager },
    { NULL,                 NULL },
};

int
main(int argc, char **argv)
{
    struct TestEntry *ent;
    int ret = 0;

    g_type_init ();

    setup();

    for (ent = test_table; ent->test != NULL; ++ent) {
        ret = ent->func ();
        if (ret < 0)
            break;
    }
    if (ent->test == NULL)
        fprintf (stderr, "\n\n===== Congratulations! All test pass!\n");
    else
        fprintf (stderr, "\n\n===== Test not pass!\n");

    teardown ();

    return ret;
}


/* ---------------- Deprecated Tests ---------------- */
# if 0
static int
test_checkout ()
{
    SeafRepo *repo;
    char *file_a, *file_b, *file_c, *dfc;
    FILE *fp_a, *fp_c, *fp_dfc;
    char cmd[1024];
    GError *error = NULL;

    printf ("\n=== test checkout\n\n");

    repo = create_repo ("checkout");

    first_commit (repo);

    sleep (2);

    printf ("*** creating branch \"test\"\n");
    /* create branch "test". */
    if (seafile_branch_add (repo->id, "test", NULL, &error) < 0) {
        fprintf (stderr, "Failed to create branch: %s.\n", error->message);
        return -1;
    }

    file_a = g_build_path (PATH_SEPERATOR, WORKTREE_DIR, repo->id, "data/test-a", NULL);
    file_b = g_build_path (PATH_SEPERATOR, WORKTREE_DIR, repo->id, "data/golden-gate.jpg", NULL);
    file_c = g_build_path (PATH_SEPERATOR, WORKTREE_DIR, repo->id, "data/a/test-b", NULL);
    dfc = g_build_path (PATH_SEPERATOR, WORKTREE_DIR, repo->id, "data/c", NULL);

    printf ("*** modifying worktree.\n");
    /* modify an existing file. */
    fp_a = g_fopen (file_a, "wb");
    if (!fp_a) {
        fprintf (stderr, "Failed to open %s: %s\n", file_a, strerror(errno));
        return -1;
    }
    fprintf (fp_a, "xyzxyz\nxyzxyz");
    fclose (fp_a);

    /* delete a file. */
    (void) g_unlink (file_b);

    /* add a new file. */
    fp_c = g_fopen (file_c, "w+b");
    if (!fp_c) {
        fprintf (stderr, "Failed to open %s: %s\n", file_c, strerror(errno));
        return -1;
    }
    fprintf (fp_c, "abcabc\nabcabc");
    fclose (fp_c);

    /* create directory-file conflict. */
    snprintf (cmd, 1024, "rm -r %s", dfc);
    int ret = system (cmd);
    if (ret < 0 || WEXITSTATUS(ret) != 0) {
        fprintf (stderr, "Failed to remove %s\n", dfc);
        return -1;
    }

    fp_dfc = g_fopen (dfc, "w+b");
    if (!fp_dfc) {
        fprintf (stderr, "Failed to open %s: %s\n", dfc, strerror(errno));
        return -1;
    }
    fprintf (fp_dfc, "1234\n1234\n");
    fclose (fp_dfc);

    sleep (2);

    printf ("*** create new commit on local.\n");
    if (seaf_repo_index_add (repo, "") < 0) {
        fprintf (stderr, "Failed to add\n");
        return -1;
    }

    /* a new commit. */
    if (!seaf_repo_index_commit (repo, "second commit")) {
        fprintf (stderr, "Failed to commit\n");
        return -1;
    }

    printf ("*** checkout branch test.\n");
    /* check out branch test. */
    if (seafile_checkout (repo->id, "test", &error) < 0) {
        fprintf (stderr, "Failed to checkout branch 'test'.\n");
        fprintf (stderr, "Checkout error messages:\n%s", error->message);
        return -1;
    }

    printf ("*** check result of checkout.\n");

    if (check_file_content (file_a, "abc123\nabc123", 13) < 0) {
        return -1;
    }

    if (g_access (file_b, F_OK) != 0) {
        fprintf (stderr, "Bug: %s should exist.\n", file_b);
        return -1;
    }

    if (g_access (file_c, F_OK) == 0) {
        fprintf (stderr, "Bug: %s should not exist.\n", file_c);
        return -1;
    }

    if (check_dir (dfc) < 0) {
        fprintf (stderr, "Bug: Directory %s should exist.\n", dfc);
        return -1;
    }

    printf ("\n=== Checkout succeeded.\n\n");
    return 0;
}

static int test_checkout_error ()
{
    SeafRepo *repo;
    char *file_a, *file_b, *file_c;
    FILE *fp_a, *fp_b, *fp_c;
    GError *error = NULL;

    printf ("\n=== test checkout error\n\n");

    repo = create_repo ("checkout_error");

    first_commit (repo);

    sleep (2);

    printf ("*** creating branch \"test\"\n");
    /* create branch "test". */
    if (seafile_branch_add (repo->id, "test", NULL, &error) < 0) {
        fprintf (stderr, "Failed to create branch: %s.\n", error->message);
        return -1;
    }

    file_a = g_build_path (PATH_SEPERATOR, WORKTREE_DIR, repo->id, "data/test-a", NULL);
    file_b = g_build_path (PATH_SEPERATOR, WORKTREE_DIR, repo->id, "data/a/test-b", NULL);
    file_c = g_build_path (PATH_SEPERATOR, WORKTREE_DIR, repo->id, "data/golden-gate.jpg", NULL);

    printf ("*** modifying worktree.\n");
    /* modify an existing file. */
    fp_a = g_fopen (file_a, "wb");
    if (!fp_a) {
        fprintf (stderr, "Failed to open %s: %s\n", file_a, strerror(errno));
        return -1;
    }
    fprintf (fp_a, "xyzxyz\nxyzxyz");
    fclose (fp_a);

    /* add a new file. */
    fp_b = g_fopen (file_b, "w+b");
    if (!fp_b) {
        fprintf (stderr, "Failed to open %s: %s\n", file_b, strerror(errno));
        return -1;
    }
    fprintf (fp_b, "abcabc\nabcabc");
    fclose (fp_b);

    /* delete a file. */
    (void) g_unlink (file_c);

    sleep (2);

    printf ("*** create new commit on local.\n");
    if (seaf_repo_index_add (repo, "") < 0) {
        fprintf (stderr, "Failed to add\n");
        return -1;
    }

    /* a new commit. */
    if (!seaf_repo_index_commit (repo, "second commit")) {
        fprintf (stderr, "Failed to commit\n");
        return -1;
    }    

    sleep (2);

    /* Test 1: overwrite local changes in worktree file. */
    fp_a = g_fopen (file_a, "wb");
    if (!fp_a) {
        fprintf (stderr, "Failed to open %s: %s\n", file_a, strerror(errno));
        return -1;
    }
    fprintf (fp_a, "123\n");
    fclose (fp_a);

    /* Test 2: overwrite untracked file. */
    fp_b = g_fopen (file_b, "w+b");
    if (!fp_b) {
        fprintf (stderr, "Failed to open %s: %s\n", file_b, strerror(errno));
        return -1;
    }
    fprintf (fp_b, "123\n");
    fclose (fp_b);

    /* Test 3: remove worktree file with local changes. */
    fp_c = g_fopen (file_c, "wb");
    if (!fp_c) {
        fprintf (stderr, "Failed to open %s: %s\n", file_c, strerror(errno));
        return -1;
    }
    fprintf (fp_c, "123\n");
    fclose (fp_c);

    sleep (2);

    if (seafile_checkout (repo->id, "test", &error) == 0) {
        fprintf (stderr, "Checkout should fail!\n");
        return -1;
    }

    printf ("Failed to checkout branch 'test'\n");
    printf ("Checkout error messages:\n%s", error->message);

    printf ("\n=== Successfully handle checkout errors.\n\n");
    return 0;
}
#endif
