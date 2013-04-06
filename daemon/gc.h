#ifndef SEAF_GC_H
#define SEAF_GC_H

/*
 * Start GC. If another GC has been started, returns -1.
 */
int
gc_start ();

int
gc_is_started ();

#endif
