/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

void seaf_ext_log_start ();
void seaf_ext_log_stop ();

inline void seaf_ext_log_aux (char *msg, ... );

#define seaf_ext_log(format, ... )                                  \
    seaf_ext_log_aux("%s(line %d) %s: " format,                     \
                     __FILE__, __LINE__, __func__, ##__VA_ARGS__)   \
    
