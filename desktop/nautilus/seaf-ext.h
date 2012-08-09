#ifndef SEAF_EXT_H
#define SEAF_EXT_H


#define SEAF_TYPE_EXT       (seaf_ext_get_type ())
#define SEAF_EXT(obj)       (G_TYPE_CHECK_INSTANCE_CAST(obj), SEAF_TYPE_EXT, SeafExt)
#define SEAF_IS_EXT(obj)    (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAF_TYPE_EXT))


typedef struct _SeafExt SeafExt;
typedef struct _SeafExtClass SeafExtClass;

struct _SeafExt {
    GObject parent;
};


struct _SeafExtClass {
    GObjectClass parent_class;
};

#endif /* SEAF_EXT_H */
