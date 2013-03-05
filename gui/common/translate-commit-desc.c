#include <glib.h>
#include <glib/gi18n.h>
#include "translate-commit-desc.h"
#include "applet-log.h"

static inline gboolean
starts_with(const char *txt, const char *prefix)
{
    return strstr(txt, prefix) == txt;
}

static inline char *
str_replace(const char *txt,
            const char *old_content,
            const char *new_content)
{
    GError *error = NULL;
    GRegex *re = NULL;
    char *newtxt = NULL;

    re = g_regex_new (old_content, 0, 0, &error);
    if (error) {
        applet_warning ("g_regex_new: %s\n", error->message);
        goto out;
    }
    
    newtxt = g_regex_replace_literal (re, txt, -1, 0, new_content, 0, &error);
    if (error) {
        applet_warning ("g_regex_replace_literal: %s\n", error->message);
        goto out;
    }

out:
    if (re) g_regex_unref(re);
    if (error) g_error_free (error);
    return newtxt;
}

static GHashTable *operations_hash = NULL;

static const char *
translate_operation (const char *operation)
{
    const char *ret =  g_hash_table_lookup (operations_hash, operation);
    return ret ? ret : operation;
}

static char *
strlist_join (GList *l, char *sep)
{
    if (!l)
        return NULL;
    
    GString *buf = g_string_new ((char *)(l->data));
    GList *ptr = l;

    while ((ptr = ptr->next)) {
        g_string_append_printf (buf, "%s%s", sep, (char *)(ptr->data));
    }

    return g_string_free (buf, FALSE);
}

static char *
translate_line (const char *line)
{
    GError *error = NULL;
    char *op = NULL;
    char *file_name = NULL;
    char *has_more = NULL;
    char *n_more = NULL;
    char *more_type = NULL;
    GMatchInfo *info = NULL;
    char *ret = NULL;

    static GRegex *re = NULL;
    if (!re) {
        /* initialize the regular expression */
        GString *buf = g_string_new (NULL);
        GList *keys = g_hash_table_get_keys (operations_hash);
        char *operations = strlist_join (keys, "|");
                                 
        buf = g_string_new(NULL);
        g_string_append_printf (buf, "(%s) \"(.*)\"\\s?(and ([0-9]+) more (files|directories))?",
                                operations);
        re = g_regex_new (buf->str, 0, 0, &error);
        g_free (operations);
        g_list_free (keys);
        g_string_free (buf, TRUE);

        if (error) {
            applet_warning ("g_regex_new: %s\n", error->message);
            ret = g_strdup(line);
            goto out;
        }
    }

    if (!g_regex_match (re, line, 0, &info)) {
        ret = g_strdup(line);
        goto out;
    }

    op = g_match_info_fetch(info, 1);
    file_name = g_match_info_fetch(info, 2);
    has_more = g_match_info_fetch(info, 3);
    n_more = g_match_info_fetch(info, 4);
    more_type = g_match_info_fetch(info, 5);
    const char *op_trans = translate_operation(op);
    char *type;

    GString *buf = g_string_new (NULL);
    if (has_more && strlen(has_more) != 0) {
        if (g_strcmp0(more_type, "files") == 0) {
            type = _("files");
        } else {
            type = _("directories");
        };

        char *more = _("and %s more");
        char more_buf[128];
        snprintf (more_buf, sizeof(more_buf), more, n_more);
        g_string_append_printf (buf, "%s \"%s\" %s %s.", op_trans,
                                file_name, more_buf, type);
    } else {
        g_string_append_printf (buf, "%s \"%s\".", op_trans, file_name);
    }

    ret = g_string_free (buf, FALSE);

out:
    g_free (op);
    g_free (file_name);
    g_free (has_more);
    g_free (n_more);
    g_free (more_type);

    if (info)
        g_match_info_free (info);

    return ret;
}

char *
translate_commit_desc (const char *input)
{
    char *ret = NULL;
    GList *ret_list = NULL;
    
    if (!input) {
        return NULL;
    }

    if (!operations_hash) {
        operations_hash = g_hash_table_new (g_str_hash, g_str_equal);
        g_hash_table_insert (operations_hash, "Added" , _("Added"));
        g_hash_table_insert (operations_hash, "Deleted" , _("Deleted"));
        g_hash_table_insert (operations_hash, "Removed" , _("Removed"));
        g_hash_table_insert (operations_hash, "Modified" , _("Modified"));
        g_hash_table_insert (operations_hash, "Renamed" , _("Renamed"));
        g_hash_table_insert (operations_hash, "Moved" , _("Moved"));
        g_hash_table_insert (operations_hash, "Added directory" , _("Added directory"));
        g_hash_table_insert (operations_hash, "Removed directory" , _("Removed directory"));
        g_hash_table_insert (operations_hash, "Renamed directory" , _("Renamed directory"));
        g_hash_table_insert (operations_hash, "Moved directory" , _("Moved directory"));
    }

    if (starts_with(input, "Reverted repo")) {
        return str_replace(input, "Reverted repo to status at",
                          _("Reverted repo to status at"));
    } else if (starts_with(input, "Reverted file")) {
        return str_replace(input, "Reverted file to status at",
                          _("Reverted file to status at"));
    } else if (starts_with(input, "Recovered deleted directory")) {
        return str_replace(input, "Recovered deleted directory",
                          _("Recovered deleted directory"));
    } else if (starts_with(input, "Merged") || starts_with(input, "Auto merge")) {
        return g_strdup(_("Auto merge by seafile system"));
    }

    /* Use regular expression to translate commit description. Commit
     * description has two forms, e.g., 'Added "foo.txt" and 3 more files.' or
     * 'Added "foo.txt".'
     */

    char **lines = g_strsplit (input, "\n", 100);
    char **ptr = lines;
    char *line;
    while ((line = *ptr++)) {
        ret_list = g_list_prepend (ret_list, translate_line(line));
    }

    ret_list = g_list_reverse (ret_list);
    ret = strlist_join(ret_list, "\n");

    g_list_free_full (ret_list, (GDestroyNotify)g_free);
    g_strfreev (lines);

    return ret;
}
