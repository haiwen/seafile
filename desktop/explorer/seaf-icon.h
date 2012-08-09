/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef SEAF_ICON_H
#define SEAF_ICON_H

typedef struct SeafIconOverlay SeafIconOverlay;

/* IShellIconOverlayIdentifier */
struct SeafIconOverlay {
    void *virtual_table;
    unsigned int count;
};

SeafIconOverlay *seaf_icon_overlay_new ();

#endif  /* SEAF_ICON_H */
