/*
 * This file Copyright (C) 2009-2010 Mnemosyne LLC
 *
 * This file is licensed by the GPL version 2.  Works owned by the
 * Transmission project are granted a special exemption to clause 2(b)
 * so that the bulk of its code can remain under the MIT license.
 * This exemption does not extend to derived works not owned by
 * the Transmission project.
 *
 * $Id: utils.c 8686 2009-06-14 01:01:46Z charles $
 */

#include <assert.h>
#include <string.h> /* memset */

#include "bitfield.h"

Bitfield*
BitfieldConstruct( Bitfield * b, size_t bitCount )
{
    b->bitCount = bitCount;
    b->byteCount = ( bitCount + 7u ) / 8u;
    b->bits = g_new0( uint8_t, b->byteCount );
    return b;
}

Bitfield*
BitfieldDestruct( Bitfield * b )
{
    if( b )
        g_free( b->bits );
    return b;
}

void
BitfieldClear( Bitfield * bitfield )
{
    memset( bitfield->bits, 0, bitfield->byteCount );
}

int
BitfieldIsEmpty( const Bitfield * bitfield )
{
    size_t i;

    for( i = 0; i < bitfield->byteCount; ++i )
        if( bitfield->bits[i] )
            return 0;

    return 1;
}

int
BitfieldAdd( Bitfield * bitfield,
                size_t        nth )
{
    if( nth >= bitfield->bitCount )
        return -1;

    bitfield->bits[nth >> 3u] |= ( 0x80 >> ( nth & 7u ) );
    return 0;
}

/* Sets bit range [begin, end) to 1 */
int
BitfieldAddRange( Bitfield * b,
                     size_t        begin,
                     size_t        end )
{
    size_t        sb, eb;
    unsigned char sm, em;

    end--;

    if( ( end >= b->bitCount ) || ( begin > end ) )
        return -1;

    sb = begin >> 3;
    sm = ~( 0xff << ( 8 - ( begin & 7 ) ) );
    eb = end >> 3;
    em = 0xff << ( 7 - ( end & 7 ) );

    if( sb == eb )
    {
        b->bits[sb] |= ( sm & em );
    }
    else
    {
        b->bits[sb] |= sm;
        b->bits[eb] |= em;
        if( ++sb < eb )
            memset ( b->bits + sb, 0xff, eb - sb );
    }

    return 0;
}

int
BitfieldRem( Bitfield * bitfield,
                size_t        nth )
{
    if( nth >= bitfield->bitCount )
        return -1;

    bitfield->bits[nth >> 3u] &= ( 0xff7f >> ( nth & 7u ) );
    return 0;
}

/* Clears bit range [begin, end) to 0 */
int
BitfieldRemRange( Bitfield * b,
                     size_t        begin,
                     size_t        end )
{
    size_t        sb, eb;
    unsigned char sm, em;

    end--;

    if( ( end >= b->bitCount ) || ( begin > end ) )
        return -1;

    sb = begin >> 3;
    sm = 0xff << ( 8 - ( begin & 7 ) );
    eb = end >> 3;
    em = ~( 0xff << ( 7 - ( end & 7 ) ) );

    if( sb == eb )
    {
        b->bits[sb] &= ( sm | em );
    }
    else
    {
        b->bits[sb] &= sm;
        b->bits[eb] &= em;
        if( ++sb < eb )
            memset ( b->bits + sb, 0, eb - sb );
    }

    return 0;
}

Bitfield*
BitfieldOr( Bitfield * a, const Bitfield * b )
{
    uint8_t * ait = a->bits;
    const uint8_t * aend = ait + a->byteCount;
    const uint8_t * bit = b->bits;
    const uint8_t * bend = bit + b->byteCount;

    while( ait!=aend && bit!=bend )
        *ait++ |= *bit++;

    return a;
}

/* set 'a' to all the flags that were in 'a' but not 'b' */
void
BitfieldDifference( Bitfield * a, const Bitfield * b )
{
    uint8_t * ait = a->bits;
    const uint8_t * aend = ait + a->byteCount;
    const uint8_t * bit = b->bits;
    const uint8_t * bend = bit + b->byteCount;

    while( ait!=aend && bit!=bend )
        *ait++ &= ~( *bit++ );
}

size_t
BitfieldCountTrueBits( const Bitfield* b )
{
    size_t           ret = 0;
    const uint8_t *  it, *end;
    static const int trueBitCount[256] = {
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
    };

    if( !b )
        return 0;

    for( it = b->bits, end = it + b->byteCount; it != end; ++it )
        ret += trueBitCount[*it];

    return ret;
}
