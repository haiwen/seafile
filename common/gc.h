#ifndef SEAF_GC_H
#define SEAF_GC_H

/*
 * Start GC. If another GC has been started, returns -1.
 */
int
gc_start ();

/*
 * Returns progress of GC in precentage.
 * If GC is not started, returns -1.
 */
int
gc_get_progress ();

gboolean
gc_is_started ();

#endif
