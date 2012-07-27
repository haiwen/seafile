/*
 * This file Copyright (C) 2009-2010 Mnemosyne LLC
 *
 * This file is licensed by the GPL version 2.  Works owned by the
 * Transmission project are granted a special exemption to clause 2(b)
 * so that the bulk of its code can remain under the MIT license.
 * This exemption does not extend to derived works not owned by
 * the Transmission project.
 */

#ifndef BITFIELD_H
#define BITFIELD_H

#include <glib.h>
#include <sys/types.h>
#include <stdint.h>

/** @brief Implementation of the BitTorrent spec's Bitfield array of bits */
typedef struct Bitfield {
    uint8_t *  bits;
    size_t     bitCount;
    size_t     byteCount;
} Bitfield;

Bitfield* BitfieldConstruct( Bitfield*, size_t bitcount );

Bitfield* BitfieldDestruct( Bitfield* );

Bitfield*    BitfieldDup( const Bitfield* );

void         BitfieldClear( Bitfield* );

int          BitfieldAdd( Bitfield*, size_t bit );

int          BitfieldRem( Bitfield*, size_t bit );

int          BitfieldAddRange( Bitfield *, size_t begin, size_t end );

int          BitfieldRemRange( Bitfield*, size_t begin, size_t end );

void         BitfieldDifference( Bitfield *, const Bitfield * );

int          BitfieldIsEmpty( const Bitfield* );

size_t       BitfieldCountTrueBits( const Bitfield* );

Bitfield*    BitfieldOr( Bitfield*, const Bitfield* );

/** A stripped-down version of bitfieldHas to be used
    for speed when you're looping quickly.  This version
    has none of BitfieldHas()'s safety checks, so you
    need to call BitfieldTestFast() first before you
    start looping. */
static inline gboolean BitfieldHasFast( const Bitfield * b, const size_t nth )
{
    return ( b->bits[nth>>3u] << ( nth & 7u ) & 0x80 ) != 0;
}

/** @param high the highest nth bit you're going to access */
static inline gboolean BitfieldTestFast( const Bitfield * b, const size_t high )
{
    return ( b != NULL )
        && ( b->bits != NULL )
        && ( high < b->bitCount );
}

static inline gboolean BitfieldHas( const Bitfield * b, size_t nth )
{
    return BitfieldTestFast( b, nth ) && BitfieldHasFast( b, nth );
}

#endif
