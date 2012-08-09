/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef SEAF_FACTORY_H
#define SEAF_FACTORY_H

STDMETHODIMP
class_factory_query_interface(IClassFactory *this,
                              REFIID guid,
                              void **pointer);

extern IClassFactory factory;

#endif /* SEAF_FACTORY_H */
