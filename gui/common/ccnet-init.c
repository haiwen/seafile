/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef __APPLE__
#include "common.h"
#endif

#include <sys/stat.h>
#include <sys/param.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <getopt.h>
#include <glib.h>
#include <glib/gstdio.h>

#include <ccnet/option.h>

#include "rsa.h"
#include "utils.h"
#include "ccnet-init.h"
#include "seafile-applet.h"


/* Number of bits in the RSA/DSA key.  This value can be set on the command line. */
#define DEFAULT_BITS        2048
static guint32 bits = 0;

static RSA *peer_privkey, *peer_pubkey;

static const char *user_name;
static const char *peer_name;

static char *peer_id;

static int make_configure_file (const char *config_file);


static int mkdir_if_not_exist (const char *dir)
{
    if (g_file_test(dir, G_FILE_TEST_IS_DIR | G_FILE_TEST_EXISTS))
        return 0;

    return ccnet_mkdir(dir, 0700);
}

static void
save_privkey (RSA *key, const char *file)
{
    FILE *f;
    f = g_fopen (file, "wb");
    PEM_write_RSAPrivateKey(f, key, NULL, NULL, 0, NULL, NULL);
    fclose (f);
}

static void
create_peerkey ()
{
    peer_privkey = generate_private_key (bits);
    peer_pubkey = private_key_to_pub (peer_privkey);
}

static char *get_peer_name ()
{
    int ret;
    char buf[256];
    char computer_name[128];

    memset(computer_name, 0, sizeof(computer_name));
    gethostname (computer_name, sizeof(computer_name));

    ret = snprintf (buf, 255, "%s@%s", user_name, computer_name);
    return g_strdup(buf);
}

static int
make_configure_file (const char *config_file)
{
    FILE *fp;

    if ((fp = g_fopen(config_file, "wb")) == NULL) {
        fprintf (stderr, "Open config file %s error: %s\n",
                 config_file, strerror(errno));
        return ERR_CONF_FILE;
    }

    fprintf (fp, "[General]\n");
    fprintf (fp, "USER_NAME = %s\n", user_name);
    fprintf (fp, "ID = %s\n", peer_id);
    fprintf (fp, "NAME = %s\n", peer_name);
    fprintf (fp, "\n");

    fprintf (fp, "[Network]\n");
    fprintf (fp, "PORT = 10001\n");
    fprintf (fp, "\n");

    fprintf (fp, "[Client]\n");
    fprintf (fp, "PORT = 13419\n");

    fclose (fp);

    fprintf (stdout, "done\n");
    return 0;
}


static int make_config_dir()
{
    int err = 0;
    char *identity_file_peer;
    char *config_file;

    create_peerkey ();
    peer_name = get_peer_name();

    peer_id = id_from_pubkey (peer_pubkey);
    identity_file_peer = g_build_filename (applet->config_dir, PEER_KEYFILE, NULL);

    /* create dir */
    if (mkdir_if_not_exist(applet->config_dir) < 0) {
        fprintf (stderr, "Make dir %s error: %s\n", 
                 applet->config_dir, strerror(errno));
        return ERR_PERMISSION;
    }

    /* save key */
    save_privkey (peer_privkey, identity_file_peer);

    /* make configure file */
    config_file = g_build_filename (applet->config_dir, CONFIG_FILE_NAME, NULL);
    err = make_configure_file (config_file);
    if (err)
        return err;

    printf ("Successly create configuration dir %s.\n", applet->config_dir);
    return 0;
}

int create_new (void)
{
    SSLeay_add_all_algorithms();

    if (bits == 0)
        bits = DEFAULT_BITS;

    user_name = g_get_user_name();
    return make_config_dir();
}

gboolean
is_valid_username(const char *username, int len)
{
    if (!username || len < 2 || len > 16)
        return FALSE;
    const char *p = username;
    while (*p && p < username +len) {
      if (!isascii(*p) ||
	  (!isalnum(*p) && *p != '_' && *p != '-'))
            return FALSE;
        ++p;
    }
    return TRUE;
}
gboolean is_valid_path(const char *path, int len)
{
    if (!path || *path == '(')
        return FALSE;
    return  TRUE;
}

