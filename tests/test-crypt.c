#include <glib.h>
#include <glib/gprintf.h>
#include <string.h>
#include "seafile-crypt.h"


#define CODE "this_is_user_passwd"

static int crypt_test (unsigned int len)
{    

    if (len <= 0) {
        g_printf (" [%s] line %d: len must be positive.\n", __func__, __LINE__);
        return -1;
    }
    
    char *msg = "Hello World!\n";
    
    GString *gstr = g_string_new (NULL);

    while (gstr->len < len) {
        g_string_append (gstr, msg);
    }

    char *enc_out = NULL;
    int enc_out_len;

    g_printf ("[setup] The input is %d bytes\n", len);
    
    int res = seafile_encrypt (&enc_out,
                               &enc_out_len,
                               gstr->str,
                               len,
                               CODE,
                               strlen(CODE));

    if (res == 0 && enc_out_len != -1)
        g_printf ("[ENC] [PASS] Encrypted output length is %d bytes\n", enc_out_len);
    else {
        g_printf ("[ENC] FAILED.\n");
        goto error;
    }

    char *dec_out = NULL;
    int dec_len;
    
    res = seafile_decrypt (&dec_out,
                           &dec_len,
                           enc_out,
                           enc_out_len,
                           CODE,
                           strlen(CODE));

    
    if (res != 0 || (unsigned int)dec_len != len ||
        strncmp (dec_out, gstr->str, len) != 0) {
       
        g_printf ("[DEC] FAILED.\n");
        goto error;
    }                
    else
        g_printf ("[DEC] [PASS] Decrypted output is the totally same as input\n");
        
    g_string_free (gstr, TRUE);
    g_free (enc_out);
    g_free (dec_out);

    g_printf ("[TEST] Finished Successfully.\n");

    return 0;
    
    
error:    

    g_string_free (gstr, TRUE);
    g_free (enc_out);
    g_free (dec_out);

    g_printf ("[TEST] FAILED.\n");
    
    return -1;

}


int main (void)
{
    unsigned int len[7] = {1, 8, 16, 50, 111, 1111, 11111};

    int i;

    for (i = 0; i < 7; i ++) {
        if (crypt_test (len[i]) != 0) {
            g_printf ("TEST FAILED.\n");
            return -1;
        }
    }

    
    g_printf ("ALL TESTS FINISHED SUCCESSFULLY.\n");

    return 0;
}

        
