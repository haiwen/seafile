
inline static gchar *
searpc_signature_int__void(void)
{
    return searpc_compute_signature ("int", 0);
}


inline static gchar *
searpc_signature_int__int(void)
{
    return searpc_compute_signature ("int", 1, "int");
}


inline static gchar *
searpc_signature_int__int_int(void)
{
    return searpc_compute_signature ("int", 2, "int", "int");
}


inline static gchar *
searpc_signature_int__int_string(void)
{
    return searpc_compute_signature ("int", 2, "int", "string");
}


inline static gchar *
searpc_signature_int__int_string_int(void)
{
    return searpc_compute_signature ("int", 3, "int", "string", "int");
}


inline static gchar *
searpc_signature_int__int_string_string(void)
{
    return searpc_compute_signature ("int", 3, "int", "string", "string");
}


inline static gchar *
searpc_signature_int__int_string_int_int(void)
{
    return searpc_compute_signature ("int", 4, "int", "string", "int", "int");
}


inline static gchar *
searpc_signature_int__int_int_string_string(void)
{
    return searpc_compute_signature ("int", 4, "int", "int", "string", "string");
}


inline static gchar *
searpc_signature_int__string(void)
{
    return searpc_compute_signature ("int", 1, "string");
}


inline static gchar *
searpc_signature_int__string_int(void)
{
    return searpc_compute_signature ("int", 2, "string", "int");
}


inline static gchar *
searpc_signature_int__string_int_int(void)
{
    return searpc_compute_signature ("int", 3, "string", "int", "int");
}


inline static gchar *
searpc_signature_int__string_int_string(void)
{
    return searpc_compute_signature ("int", 3, "string", "int", "string");
}


inline static gchar *
searpc_signature_int__string_int_string_string(void)
{
    return searpc_compute_signature ("int", 4, "string", "int", "string", "string");
}


inline static gchar *
searpc_signature_int__string_int_int_string_string(void)
{
    return searpc_compute_signature ("int", 5, "string", "int", "int", "string", "string");
}


inline static gchar *
searpc_signature_int__string_string(void)
{
    return searpc_compute_signature ("int", 2, "string", "string");
}


inline static gchar *
searpc_signature_int__string_string_string(void)
{
    return searpc_compute_signature ("int", 3, "string", "string", "string");
}


inline static gchar *
searpc_signature_int__string_string_int_int(void)
{
    return searpc_compute_signature ("int", 4, "string", "string", "int", "int");
}


inline static gchar *
searpc_signature_int__string_string_string_int(void)
{
    return searpc_compute_signature ("int", 4, "string", "string", "string", "int");
}


inline static gchar *
searpc_signature_int__string_string_string_int_string(void)
{
    return searpc_compute_signature ("int", 5, "string", "string", "string", "int", "string");
}


inline static gchar *
searpc_signature_int__string_string_string_string(void)
{
    return searpc_compute_signature ("int", 4, "string", "string", "string", "string");
}


inline static gchar *
searpc_signature_int__string_string_string_string_string(void)
{
    return searpc_compute_signature ("int", 5, "string", "string", "string", "string", "string");
}


inline static gchar *
searpc_signature_int__string_string_string_string_string_string(void)
{
    return searpc_compute_signature ("int", 6, "string", "string", "string", "string", "string", "string");
}


inline static gchar *
searpc_signature_int__string_string_string_int_string_string(void)
{
    return searpc_compute_signature ("int", 6, "string", "string", "string", "int", "string", "string");
}


inline static gchar *
searpc_signature_int__string_string_string_string_string_string_string(void)
{
    return searpc_compute_signature ("int", 7, "string", "string", "string", "string", "string", "string", "string");
}


inline static gchar *
searpc_signature_int__string_int64(void)
{
    return searpc_compute_signature ("int", 2, "string", "int64");
}


inline static gchar *
searpc_signature_int__int_int64(void)
{
    return searpc_compute_signature ("int", 2, "int", "int64");
}


inline static gchar *
searpc_signature_int__int_string_int64(void)
{
    return searpc_compute_signature ("int", 3, "int", "string", "int64");
}


inline static gchar *
searpc_signature_int64__void(void)
{
    return searpc_compute_signature ("int64", 0);
}


inline static gchar *
searpc_signature_int64__string(void)
{
    return searpc_compute_signature ("int64", 1, "string");
}


inline static gchar *
searpc_signature_int64__int(void)
{
    return searpc_compute_signature ("int64", 1, "int");
}


inline static gchar *
searpc_signature_int64__int_string(void)
{
    return searpc_compute_signature ("int64", 2, "int", "string");
}


inline static gchar *
searpc_signature_int64__string_int_string(void)
{
    return searpc_compute_signature ("int64", 3, "string", "int", "string");
}


inline static gchar *
searpc_signature_string__void(void)
{
    return searpc_compute_signature ("string", 0);
}


inline static gchar *
searpc_signature_string__int(void)
{
    return searpc_compute_signature ("string", 1, "int");
}


inline static gchar *
searpc_signature_string__int_int(void)
{
    return searpc_compute_signature ("string", 2, "int", "int");
}


inline static gchar *
searpc_signature_string__int_string(void)
{
    return searpc_compute_signature ("string", 2, "int", "string");
}


inline static gchar *
searpc_signature_string__int_int_string(void)
{
    return searpc_compute_signature ("string", 3, "int", "int", "string");
}


inline static gchar *
searpc_signature_string__string(void)
{
    return searpc_compute_signature ("string", 1, "string");
}


inline static gchar *
searpc_signature_string__string_int(void)
{
    return searpc_compute_signature ("string", 2, "string", "int");
}


inline static gchar *
searpc_signature_string__string_int_int(void)
{
    return searpc_compute_signature ("string", 3, "string", "int", "int");
}


inline static gchar *
searpc_signature_string__string_string(void)
{
    return searpc_compute_signature ("string", 2, "string", "string");
}


inline static gchar *
searpc_signature_string__string_string_int(void)
{
    return searpc_compute_signature ("string", 3, "string", "string", "int");
}


inline static gchar *
searpc_signature_string__string_string_int_int(void)
{
    return searpc_compute_signature ("string", 4, "string", "string", "int", "int");
}


inline static gchar *
searpc_signature_string__string_string_string(void)
{
    return searpc_compute_signature ("string", 3, "string", "string", "string");
}


inline static gchar *
searpc_signature_string__string_string_string_string(void)
{
    return searpc_compute_signature ("string", 4, "string", "string", "string", "string");
}


inline static gchar *
searpc_signature_string__string_string_string_string_int(void)
{
    return searpc_compute_signature ("string", 5, "string", "string", "string", "string", "int");
}


inline static gchar *
searpc_signature_string__string_string_string_string_string(void)
{
    return searpc_compute_signature ("string", 5, "string", "string", "string", "string", "string");
}


inline static gchar *
searpc_signature_string__string_string_string_string_string_int(void)
{
    return searpc_compute_signature ("string", 6, "string", "string", "string", "string", "string", "int");
}


inline static gchar *
searpc_signature_string__string_string_string_string_string_string_int(void)
{
    return searpc_compute_signature ("string", 7, "string", "string", "string", "string", "string", "string", "int");
}


inline static gchar *
searpc_signature_string__string_string_string_string_string_string_int_int(void)
{
    return searpc_compute_signature ("string", 8, "string", "string", "string", "string", "string", "string", "int", "int");
}


inline static gchar *
searpc_signature_string__string_string_string_string_string_string(void)
{
    return searpc_compute_signature ("string", 6, "string", "string", "string", "string", "string", "string");
}


inline static gchar *
searpc_signature_string__string_string_string_string_string_string_int64(void)
{
    return searpc_compute_signature ("string", 7, "string", "string", "string", "string", "string", "string", "int64");
}


inline static gchar *
searpc_signature_string__string_string_string_string_string_string_int64_int(void)
{
    return searpc_compute_signature ("string", 8, "string", "string", "string", "string", "string", "string", "int64", "int");
}


inline static gchar *
searpc_signature_string__string_string_string_string_string_string_string(void)
{
    return searpc_compute_signature ("string", 7, "string", "string", "string", "string", "string", "string", "string");
}


inline static gchar *
searpc_signature_string__string_string_string_string_string_string_string_int64(void)
{
    return searpc_compute_signature ("string", 8, "string", "string", "string", "string", "string", "string", "string", "int64");
}


inline static gchar *
searpc_signature_string__string_string_string_string_string_string_string_string_string(void)
{
    return searpc_compute_signature ("string", 9, "string", "string", "string", "string", "string", "string", "string", "string", "string");
}


inline static gchar *
searpc_signature_string__string_int_string_string_string_string_string_string_string_int_string(void)
{
    return searpc_compute_signature ("string", 11, "string", "int", "string", "string", "string", "string", "string", "string", "string", "int", "string");
}


inline static gchar *
searpc_signature_string__string_int_string_int_int(void)
{
    return searpc_compute_signature ("string", 5, "string", "int", "string", "int", "int");
}


inline static gchar *
searpc_signature_string__string_int_string_string_string(void)
{
    return searpc_compute_signature ("string", 5, "string", "int", "string", "string", "string");
}


inline static gchar *
searpc_signature_objlist__void(void)
{
    return searpc_compute_signature ("objlist", 0);
}


inline static gchar *
searpc_signature_objlist__int(void)
{
    return searpc_compute_signature ("objlist", 1, "int");
}


inline static gchar *
searpc_signature_objlist__int_int(void)
{
    return searpc_compute_signature ("objlist", 2, "int", "int");
}


inline static gchar *
searpc_signature_objlist__int_string(void)
{
    return searpc_compute_signature ("objlist", 2, "int", "string");
}


inline static gchar *
searpc_signature_objlist__int_int_int(void)
{
    return searpc_compute_signature ("objlist", 3, "int", "int", "int");
}


inline static gchar *
searpc_signature_objlist__string(void)
{
    return searpc_compute_signature ("objlist", 1, "string");
}


inline static gchar *
searpc_signature_objlist__string_int(void)
{
    return searpc_compute_signature ("objlist", 2, "string", "int");
}


inline static gchar *
searpc_signature_objlist__string_int_int(void)
{
    return searpc_compute_signature ("objlist", 3, "string", "int", "int");
}


inline static gchar *
searpc_signature_objlist__string_int_string(void)
{
    return searpc_compute_signature ("objlist", 3, "string", "int", "string");
}


inline static gchar *
searpc_signature_objlist__string_string(void)
{
    return searpc_compute_signature ("objlist", 2, "string", "string");
}


inline static gchar *
searpc_signature_objlist__string_string_string(void)
{
    return searpc_compute_signature ("objlist", 3, "string", "string", "string");
}


inline static gchar *
searpc_signature_objlist__string_string_int(void)
{
    return searpc_compute_signature ("objlist", 3, "string", "string", "int");
}


inline static gchar *
searpc_signature_objlist__string_string_string_int(void)
{
    return searpc_compute_signature ("objlist", 4, "string", "string", "string", "int");
}


inline static gchar *
searpc_signature_objlist__string_string_int_int(void)
{
    return searpc_compute_signature ("objlist", 4, "string", "string", "int", "int");
}


inline static gchar *
searpc_signature_objlist__string_string_int_int_int(void)
{
    return searpc_compute_signature ("objlist", 5, "string", "string", "int", "int", "int");
}


inline static gchar *
searpc_signature_objlist__int_string_string_int_int(void)
{
    return searpc_compute_signature ("objlist", 5, "int", "string", "string", "int", "int");
}


inline static gchar *
searpc_signature_objlist__string_int_string_string_string(void)
{
    return searpc_compute_signature ("objlist", 5, "string", "int", "string", "string", "string");
}


inline static gchar *
searpc_signature_objlist__string_int_string_int_int(void)
{
    return searpc_compute_signature ("objlist", 5, "string", "int", "string", "int", "int");
}


inline static gchar *
searpc_signature_objlist__string_int_string_string_int(void)
{
    return searpc_compute_signature ("objlist", 5, "string", "int", "string", "string", "int");
}


inline static gchar *
searpc_signature_objlist__string_string_string_string_int_int(void)
{
    return searpc_compute_signature ("objlist", 6, "string", "string", "string", "string", "int", "int");
}


inline static gchar *
searpc_signature_object__int(void)
{
    return searpc_compute_signature ("object", 1, "int");
}


inline static gchar *
searpc_signature_object__string(void)
{
    return searpc_compute_signature ("object", 1, "string");
}


inline static gchar *
searpc_signature_object__string_string(void)
{
    return searpc_compute_signature ("object", 2, "string", "string");
}


inline static gchar *
searpc_signature_object__string_string_string(void)
{
    return searpc_compute_signature ("object", 3, "string", "string", "string");
}


inline static gchar *
searpc_signature_object__string_int_string(void)
{
    return searpc_compute_signature ("object", 3, "string", "int", "string");
}


inline static gchar *
searpc_signature_object__int_string_string(void)
{
    return searpc_compute_signature ("object", 3, "int", "string", "string");
}


inline static gchar *
searpc_signature_object__int_string_string_string_string(void)
{
    return searpc_compute_signature ("object", 5, "int", "string", "string", "string", "string");
}


inline static gchar *
searpc_signature_object__string_string_string_string_string_string_string_int_int(void)
{
    return searpc_compute_signature ("object", 9, "string", "string", "string", "string", "string", "string", "string", "int", "int");
}


inline static gchar *
searpc_signature_object__string_string_string_string_string_string_int_string_int_int(void)
{
    return searpc_compute_signature ("object", 10, "string", "string", "string", "string", "string", "string", "int", "string", "int", "int");
}


inline static gchar *
searpc_signature_json__void(void)
{
    return searpc_compute_signature ("json", 0);
}

