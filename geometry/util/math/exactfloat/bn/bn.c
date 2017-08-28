/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include "../bn/bn.h"
#include "../bn/crypto.h"
#include "../bn/err.h"

#include "stddef.h"
#include "stdio.h"

void BN_init(BIGNUM *a)
{
    memset(a, 0, sizeof(BIGNUM));
    bn_check_top(a);
}

BIGNUM *BN_new(void)
{
    BIGNUM *ret;

    if ((ret = (BIGNUM *)OPENSSL_malloc(sizeof(BIGNUM))) == NULL) {
        BNerr(BN_F_BN_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    ret->flags = BN_FLG_MALLOCED;
    ret->top = 0;
    ret->neg = 0;
    ret->dmax = 0;
    ret->d = NULL;
    bn_check_top(ret);
    return (ret);
}

BIGNUM *BN_dup(const BIGNUM *a)
{
    BIGNUM *t;

    if (a == NULL)
        return NULL;
    bn_check_top(a);

    t = BN_new();
    if (t == NULL)
        return NULL;
    if (!BN_copy(t, a)) {
        BN_free(t);
        return NULL;
    }
    bn_check_top(t);
    return t;
}

BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)
{
    int i;
    BN_ULONG *A;
    const BN_ULONG *B;

    bn_check_top(b);

    if (a == b)
        return (a);
    if (bn_wexpand(a, b->top) == NULL)
        return (NULL);

#if 1
    A = a->d;
    B = b->d;
    for (i = b->top >> 2; i > 0; i--, A += 4, B += 4) {
        BN_ULONG a0, a1, a2, a3;
        a0 = B[0];
        a1 = B[1];
        a2 = B[2];
        a3 = B[3];
        A[0] = a0;
        A[1] = a1;
        A[2] = a2;
        A[3] = a3;
    }
    /* ultrix cc workaround, see comments in bn_expand_internal */
    switch (b->top & 3) {
    case 3:
        A[2] = B[2];
    case 2:
        A[1] = B[1];
    case 1:
        A[0] = B[0];
    case 0:;
    }
#else
    memcpy(a->d, b->d, sizeof(b->d[0]) * b->top);
#endif

    a->top = b->top;
    a->neg = b->neg;
    bn_check_top(a);
    return (a);
}

void BN_clear(BIGNUM *a)
{
    bn_check_top(a);
    if (a->d != NULL)
        OPENSSL_cleanse(a->d, a->dmax * sizeof(a->d[0]));
    a->top = 0;
    a->neg = 0;
}

void BN_clear_free(BIGNUM *a)
{
    int i;

    if (a == NULL)
        return;
    bn_check_top(a);
    if (a->d != NULL) {
        OPENSSL_cleanse(a->d, a->dmax * sizeof(a->d[0]));
        if (!(BN_get_flags(a, BN_FLG_STATIC_DATA)))
            OPENSSL_free(a->d);
    }
    i = BN_get_flags(a, BN_FLG_MALLOCED);
    OPENSSL_cleanse(a, sizeof(BIGNUM));
    if (i)
        OPENSSL_free(a);
}

void BN_free(BIGNUM *a)
{
    if (a == NULL)
        return;
    bn_check_top(a);
    if ((a->d != NULL) && !(BN_get_flags(a, BN_FLG_STATIC_DATA)))
        OPENSSL_free(a->d);
    if (a->flags & BN_FLG_MALLOCED)
        OPENSSL_free(a);
    else {
#ifndef OPENSSL_NO_DEPRECATED
        a->flags |= BN_FLG_FREE;
#endif
        a->d = NULL;
    }
}

void BN_set_negative(BIGNUM *a, int b)
{
    if (b && !BN_is_zero(a))
        a->neg = 1;
    else
        a->neg = 0;
}

int BN_is_bit_set(const BIGNUM *a, int n)
{
    int i, j;

    bn_check_top(a);
    if (n < 0)
        return 0;
    i = n / BN_BITS2;
    j = n % BN_BITS2;
    if (a->top <= i)
        return 0;
    return (int)(((a->d[i]) >> j) & ((BN_ULONG)1));
}

int BN_num_bits_word(BN_ULONG l)
{
    static const unsigned char bits[256] = {
        0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    };

#if defined(SIXTY_FOUR_BIT_LONG)
    if (l & 0xffffffff00000000L) {
        if (l & 0xffff000000000000L) {
            if (l & 0xff00000000000000L) {
                return (bits[(int)(l >> 56)] + 56);
            } else
                return (bits[(int)(l >> 48)] + 48);
        } else {
            if (l & 0x0000ff0000000000L) {
                return (bits[(int)(l >> 40)] + 40);
            } else
                return (bits[(int)(l >> 32)] + 32);
        }
    } else
#else
# ifdef SIXTY_FOUR_BIT
    if (l & 0xffffffff00000000LL) {
        if (l & 0xffff000000000000LL) {
            if (l & 0xff00000000000000LL) {
                return (bits[(int)(l >> 56)] + 56);
            } else
                return (bits[(int)(l >> 48)] + 48);
        } else {
            if (l & 0x0000ff0000000000LL) {
                return (bits[(int)(l >> 40)] + 40);
            } else
                return (bits[(int)(l >> 32)] + 32);
        }
    } else
# endif
#endif
    {
#if defined(THIRTY_TWO_BIT) || defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
        if (l & 0xffff0000L) {
            if (l & 0xff000000L)
                return (bits[(int)(l >> 24L)] + 24);
            else
                return (bits[(int)(l >> 16L)] + 16);
        } else
#endif
        {
#if defined(THIRTY_TWO_BIT) || defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
            if (l & 0xff00L)
                return (bits[(int)(l >> 8)] + 8);
            else
#endif
                return (bits[(int)(l)]);
        }
    }
}

int BN_num_bits(const BIGNUM *a)
{
    int i = a->top - 1;
    bn_check_top(a);

    if (BN_is_zero(a))
        return 0;
    return ((i * BN_BITS2) + BN_num_bits_word(a->d[i]));
}

/* This is used both by bn_expand2() and bn_dup_expand() */
/* The caller MUST check that words > b->dmax before calling this */
static BN_ULONG *bn_expand_internal(const BIGNUM *b, int words)
{
    BN_ULONG *A, *a = NULL;
    const BN_ULONG *B;
    int i;

    bn_check_top(b);

    if (words > (INT_MAX / (4 * BN_BITS2))) {
        BNerr(BN_F_BN_EXPAND_INTERNAL, BN_R_BIGNUM_TOO_LONG);
        return NULL;
    }
    if (BN_get_flags(b, BN_FLG_STATIC_DATA)) {
        BNerr(BN_F_BN_EXPAND_INTERNAL, BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);
        return (NULL);
    }
    a = A = (BN_ULONG *)OPENSSL_malloc(sizeof(BN_ULONG) * words);
    if (A == NULL) {
        BNerr(BN_F_BN_EXPAND_INTERNAL, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
#ifdef PURIFY
    /*
     * Valgrind complains in BN_consttime_swap because we process the whole
     * array even if it's not initialised yet. This doesn't matter in that
     * function - what's important is constant time operation (we're not
     * actually going to use the data)
     */
    memset(a, 0, sizeof(BN_ULONG) * words);
#endif

#if 1
    B = b->d;
    /* Check if the previous number needs to be copied */
    if (B != NULL) {
        for (i = b->top >> 2; i > 0; i--, A += 4, B += 4) {
            /*
             * The fact that the loop is unrolled
             * 4-wise is a tribute to Intel. It's
             * the one that doesn't have enough
             * registers to accomodate more data.
             * I'd unroll it 8-wise otherwise:-)
             *
             *              <appro@fy.chalmers.se>
             */
            BN_ULONG a0, a1, a2, a3;
            a0 = B[0];
            a1 = B[1];
            a2 = B[2];
            a3 = B[3];
            A[0] = a0;
            A[1] = a1;
            A[2] = a2;
            A[3] = a3;
        }
        /*
         * workaround for ultrix cc: without 'case 0', the optimizer does
         * the switch table by doing a=top&3; a--; goto jump_table[a];
         * which fails for top== 0
         */
        switch (b->top & 3) {
        case 3:
            A[2] = B[2];
        case 2:
            A[1] = B[1];
        case 1:
            A[0] = B[0];
        case 0:
            ;
        }
    }
#else
    memset(A, 0, sizeof(BN_ULONG) * words);
    memcpy(A, b->d, sizeof(b->d[0]) * b->top);
#endif

    return (a);
}

BIGNUM *bn_expand2(BIGNUM *b, int words)
{
    bn_check_top(b);

    if (words > b->dmax) {
        BN_ULONG *a = bn_expand_internal(b, words);
        if (!a)
            return NULL;
        if (b->d)
            OPENSSL_free(b->d);
        b->d = a;
        b->dmax = words;
    }

/* None of this should be necessary because of what b->top means! */
#if 0
    /*
     * NB: bn_wexpand() calls this only if the BIGNUM really has to grow
     */
    if (b->top < b->dmax) {
        int i;
        BN_ULONG *A = &(b->d[b->top]);
        for (i = (b->dmax - b->top) >> 3; i > 0; i--, A += 8) {
            A[0] = 0;
            A[1] = 0;
            A[2] = 0;
            A[3] = 0;
            A[4] = 0;
            A[5] = 0;
            A[6] = 0;
            A[7] = 0;
        }
        for (i = (b->dmax - b->top) & 7; i > 0; i--, A++)
            A[0] = 0;
        assert(A == &(b->d[b->dmax]));
    }
#endif
    bn_check_top(b);
    return b;
}

int bn_cmp_words(const BN_ULONG *a, const BN_ULONG *b, int n)
{
    int i;
    BN_ULONG aa, bb;

    aa = a[n - 1];
    bb = b[n - 1];
    if (aa != bb)
        return ((aa > bb) ? 1 : -1);
    for (i = n - 2; i >= 0; i--) {
        aa = a[i];
        bb = b[i];
        if (aa != bb)
            return ((aa > bb) ? 1 : -1);
    }
    return (0);
}

int bn_cmp_part_words(const BN_ULONG *a, const BN_ULONG *b, int cl, int dl)
{
    int n, i;
    n = cl - 1;

    if (dl < 0) {
        for (i = dl; i < 0; i++) {
            if (b[n - i] != 0)
                return -1;      /* a < b */
        }
    }
    if (dl > 0) {
        for (i = dl; i > 0; i--) {
            if (a[n + i] != 0)
                return 1;       /* a > b */
        }
    }
    return bn_cmp_words(a, b, cl);
}

BN_ULONG BN_get_word(const BIGNUM *a)
{
    if (a->top > 1)
        return BN_MASK2;
    else if (a->top == 1)
        return a->d[0];
    /* a->top == 0 */
    return 0;
}

int BN_set_word(BIGNUM *a, BN_ULONG w)
{
    bn_check_top(a);
    if (bn_expand(a, (int)sizeof(BN_ULONG) * 8) == NULL)
        return (0);
    a->neg = 0;
    a->d[0] = w;
    a->top = (w ? 1 : 0);
    bn_check_top(a);
    return (1);
}

int BN_add_word(BIGNUM *a, BN_ULONG w)
{
    BN_ULONG l;
    int i;

    bn_check_top(a);
    w &= BN_MASK2;

    /* degenerate case: w is zero */
    if (!w)
        return 1;
    /* degenerate case: a is zero */
    if (BN_is_zero(a))
        return BN_set_word(a, w);
    /* handle 'a' when negative */
    if (a->neg) {
        a->neg = 0;
        i = BN_sub_word(a, w);
        if (!BN_is_zero(a))
            a->neg = !(a->neg);
        return (i);
    }
    for (i = 0; w != 0 && i < a->top; i++) {
        a->d[i] = l = (a->d[i] + w) & BN_MASK2;
        w = (w > l) ? 1 : 0;
    }
    if (w && i == a->top) {
        if (bn_wexpand(a, a->top + 1) == NULL)
            return 0;
        a->top++;
        a->d[i] = w;
    }
    bn_check_top(a);
    return (1);
}

int BN_sub_word(BIGNUM *a, BN_ULONG w)
{
    int i;

    bn_check_top(a);
    w &= BN_MASK2;

    /* degenerate case: w is zero */
    if (!w)
        return 1;
    /* degenerate case: a is zero */
    if (BN_is_zero(a)) {
        i = BN_set_word(a, w);
        if (i != 0)
            BN_set_negative(a, 1);
        return i;
    }
    /* handle 'a' when negative */
    if (a->neg) {
        a->neg = 0;
        i = BN_add_word(a, w);
        a->neg = 1;
        return (i);
    }

    if ((a->top == 1) && (a->d[0] < w)) {
        a->d[0] = w - a->d[0];
        a->neg = 1;
        return (1);
    }
    i = 0;
    for (;;) {
        if (a->d[i] >= w) {
            a->d[i] -= w;
            break;
        } else {
            a->d[i] = (a->d[i] - w) & BN_MASK2;
            i++;
            w = 1;
        }
    }
    if ((a->d[i] == 0) && (i == (a->top - 1)))
        a->top--;
    bn_check_top(a);
    return (1);
}

BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w)
{
    BN_ULONG ret = 0;
    int i, j;

    bn_check_top(a);
    w &= BN_MASK2;

    if (!w)
        /* actually this an error (division by zero) */
        return (BN_ULONG)-1;
    if (a->top == 0)
        return 0;

    /* normalize input (so bn_div_words doesn't complain) */
    j = BN_BITS2 - BN_num_bits_word(w);
    w <<= j;
    if (!BN_lshift(a, a, j))
        return (BN_ULONG)-1;

    for (i = a->top - 1; i >= 0; i--) {
        BN_ULONG l, d;

        l = a->d[i];
        d = bn_div_words(ret, l, w);
        ret = (l - ((d * w) & BN_MASK2)) & BN_MASK2;
        a->d[i] = d;
    }
    if ((a->top > 0) && (a->d[a->top - 1] == 0))
        a->top--;
    ret >>= j;
    bn_check_top(a);
    return (ret);
}

int BN_lshift(BIGNUM *r, const BIGNUM *a, int n)
{
    int i, nw, lb, rb;
    BN_ULONG *t, *f;
    BN_ULONG l;

    bn_check_top(r);
    bn_check_top(a);

    if (n < 0) {
        BNerr(BN_F_BN_LSHIFT, BN_R_INVALID_SHIFT);
        return 0;
    }

    r->neg = a->neg;
    nw = n / BN_BITS2;
    if (bn_wexpand(r, a->top + nw + 1) == NULL)
        return (0);
    lb = n % BN_BITS2;
    rb = BN_BITS2 - lb;
    f = a->d;
    t = r->d;
    t[a->top + nw] = 0;
    if (lb == 0)
        for (i = a->top - 1; i >= 0; i--)
            t[nw + i] = f[i];
    else
        for (i = a->top - 1; i >= 0; i--) {
            l = f[i];
            t[nw + i + 1] |= (l >> rb) & BN_MASK2;
            t[nw + i] = (l << lb) & BN_MASK2;
        }
    memset(t, 0, nw * sizeof(t[0]));
    /*
     * for (i=0; i<nw; i++) t[i]=0;
     */
    r->top = a->top + nw + 1;
    bn_correct_top(r);
    bn_check_top(r);
    return (1);
}

int BN_rshift(BIGNUM *r, const BIGNUM *a, int n)
{
    int i, j, nw, lb, rb;
    BN_ULONG *t, *f;
    BN_ULONG l, tmp;

    bn_check_top(r);
    bn_check_top(a);

    if (n < 0) {
        BNerr(BN_F_BN_RSHIFT, BN_R_INVALID_SHIFT);
        return 0;
    }

    nw = n / BN_BITS2;
    rb = n % BN_BITS2;
    lb = BN_BITS2 - rb;
    if (nw >= a->top || a->top == 0) {
        BN_zero(r);
        return (1);
    }
    i = (BN_num_bits(a) - n + (BN_BITS2 - 1)) / BN_BITS2;
    if (r != a) {
        r->neg = a->neg;
        if (bn_wexpand(r, i) == NULL)
            return (0);
    } else {
        if (n == 0)
            return 1;           /* or the copying loop will go berserk */
    }

    f = &(a->d[nw]);
    t = r->d;
    j = a->top - nw;
    r->top = i;

    if (rb == 0) {
        for (i = j; i != 0; i--)
            *(t++) = *(f++);
    } else {
        l = *(f++);
        for (i = j - 1; i != 0; i--) {
            tmp = (l >> rb) & BN_MASK2;
            l = *(f++);
            *(t++) = (tmp | (l << lb)) & BN_MASK2;
        }
        if ((l = (l >> rb) & BN_MASK2))
            *(t) = l;
    }
    bn_check_top(r);
    return (1);
}

int BN_ucmp(const BIGNUM *a, const BIGNUM *b)
{
    int i;
    BN_ULONG t1, t2, *ap, *bp;

    bn_check_top(a);
    bn_check_top(b);

    i = a->top - b->top;
    if (i != 0)
        return (i);
    ap = a->d;
    bp = b->d;
    for (i = a->top - 1; i >= 0; i--) {
        t1 = ap[i];
        t2 = bp[i];
        if (t1 != t2)
            return ((t1 > t2) ? 1 : -1);
    }
    return (0);
}

int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int max, min, dif;
    BN_ULONG *ap, *bp, *rp, carry, t1, t2;
    const BIGNUM *tmp;

    bn_check_top(a);
    bn_check_top(b);

    if (a->top < b->top) {
        tmp = a;
        a = b;
        b = tmp;
    }
    max = a->top;
    min = b->top;
    dif = max - min;

    if (bn_wexpand(r, max + 1) == NULL)
        return 0;

    r->top = max;

    ap = a->d;
    bp = b->d;
    rp = r->d;

    carry = bn_add_words(rp, ap, bp, min);
    rp += min;
    ap += min;
    bp += min;

    if (carry) {
        while (dif) {
            dif--;
            t1 = *(ap++);
            t2 = (t1 + 1) & BN_MASK2;
            *(rp++) = t2;
            if (t2) {
                carry = 0;
                break;
            }
        }
        if (carry) {
            /* carry != 0 => dif == 0 */
            *rp = 1;
            r->top++;
        }
    }
    if (dif && rp != ap)
        while (dif--)
            /* copy remaining words if ap != rp */
            *(rp++) = *(ap++);
    r->neg = 0;
    bn_check_top(r);
    return 1;
}

int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int max, min, dif;
    register BN_ULONG t1, t2, *ap, *bp, *rp;
    int i, carry;
#if defined(IRIX_CC_BUG) && !defined(LINT)
    int dummy;
#endif

    bn_check_top(a);
    bn_check_top(b);

    max = a->top;
    min = b->top;
    dif = max - min;

    if (dif < 0) {              /* hmm... should not be happening */
        BNerr(BN_F_BN_USUB, BN_R_ARG2_LT_ARG3);
        return (0);
    }

    if (bn_wexpand(r, max) == NULL)
        return (0);

    ap = a->d;
    bp = b->d;
    rp = r->d;

#if 1
    carry = 0;
    for (i = min; i != 0; i--) {
        t1 = *(ap++);
        t2 = *(bp++);
        if (carry) {
            carry = (t1 <= t2);
            t1 = (t1 - t2 - 1) & BN_MASK2;
        } else {
            carry = (t1 < t2);
            t1 = (t1 - t2) & BN_MASK2;
        }
# if defined(IRIX_CC_BUG) && !defined(LINT)
        dummy = t1;
# endif
        *(rp++) = t1 & BN_MASK2;
    }
#else
    carry = bn_sub_words(rp, ap, bp, min);
    ap += min;
    bp += min;
    rp += min;
#endif
    if (carry) {                /* subtracted */
        if (!dif)
            /* error: a < b */
            return 0;
        while (dif) {
            dif--;
            t1 = *(ap++);
            t2 = (t1 - 1) & BN_MASK2;
            *(rp++) = t2;
            if (t1)
                break;
        }
    }
#if 0
    memcpy(rp, ap, sizeof(*rp) * (max - i));
#else
    if (rp != ap) {
        for (;;) {
            if (!dif--)
                break;
            rp[0] = ap[0];
            if (!dif--)
                break;
            rp[1] = ap[1];
            if (!dif--)
                break;
            rp[2] = ap[2];
            if (!dif--)
                break;
            rp[3] = ap[3];
            rp += 4;
            ap += 4;
        }
    }
#endif

    r->top = max;
    r->neg = 0;
    bn_correct_top(r);
    return (1);
}

int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    const BIGNUM *tmp;
    int a_neg = a->neg, ret;

    bn_check_top(a);
    bn_check_top(b);

    /*-
     *  a +  b      a+b
     *  a + -b      a-b
     * -a +  b      b-a
     * -a + -b      -(a+b)
     */
    if (a_neg ^ b->neg) {
        /* only one is negative */
        if (a_neg) {
            tmp = a;
            a = b;
            b = tmp;
        }

        /* we are now a - b */

        if (BN_ucmp(a, b) < 0) {
            if (!BN_usub(r, b, a))
                return (0);
            r->neg = 1;
        } else {
            if (!BN_usub(r, a, b))
                return (0);
            r->neg = 0;
        }
        return (1);
    }

    ret = BN_uadd(r, a, b);
    r->neg = a_neg;
    bn_check_top(r);
    return ret;
}

int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int max;
    int add = 0, neg = 0;
    const BIGNUM *tmp;

    bn_check_top(a);
    bn_check_top(b);

    /*-
     *  a -  b      a-b
     *  a - -b      a+b
     * -a -  b      -(a+b)
     * -a - -b      b-a
     */
    if (a->neg) {
        if (b->neg) {
            tmp = a;
            a = b;
            b = tmp;
        } else {
            add = 1;
            neg = 1;
        }
    } else {
        if (b->neg) {
            add = 1;
            neg = 0;
        }
    }

    if (add) {
        if (!BN_uadd(r, a, b))
            return (0);
        r->neg = neg;
        return (1);
    }

    /* We are actually doing a - b :-) */

    max = (a->top > b->top) ? a->top : b->top;
    if (bn_wexpand(r, max) == NULL)
        return (0);
    if (BN_ucmp(a, b) < 0) {
        if (!BN_usub(r, b, a))
            return (0);
        r->neg = 1;
    } else {
        if (!BN_usub(r, a, b))
            return (0);
        r->neg = 0;
    }
    bn_check_top(r);
    return (1);
}

int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    int i, bits, ret = 0;
    BIGNUM *v, *rr;

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
        BNerr(BN_F_BN_EXP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return -1;
    }

    BN_CTX_start(ctx);
    if ((r == a) || (r == p))
        rr = BN_CTX_get(ctx);
    else
        rr = r;
    v = BN_CTX_get(ctx);
    if (rr == NULL || v == NULL)
        goto err;

    if (BN_copy(v, a) == NULL)
        goto err;
    bits = BN_num_bits(p);

    if (BN_is_odd(p)) {
        if (BN_copy(rr, a) == NULL)
            goto err;
    } else {
        if (!BN_one(rr))
            goto err;
    }

    for (i = 1; i < bits; i++) {
        if (!BN_sqr(v, v, ctx))
            goto err;
        if (BN_is_bit_set(p, i)) {
            if (!BN_mul(rr, rr, v, ctx))
                goto err;
        }
    }
    if (r != rr && BN_copy(r, rr) == NULL)
        goto err;

    ret = 1;
 err:
    BN_CTX_end(ctx);
    bn_check_top(r);
    return (ret);
}

char *BN_bn2dec(const BIGNUM *a)
{
    int i = 0, num, ok = 0;
    char *buf = NULL;
    char *p;
    BIGNUM *t = NULL;
    BN_ULONG *bn_data = NULL, *lp;
    int bn_data_num;

    /*-
     * get an upper bound for the length of the decimal integer
     * num <= (BN_num_bits(a) + 1) * log(2)
     *     <= 3 * BN_num_bits(a) * 0.1001 + log(2) + 1     (rounding error)
     *     <= BN_num_bits(a)/10 + BN_num_bits/1000 + 1 + 1
     */
    i = BN_num_bits(a) * 3;
    num = (i / 10 + i / 1000 + 1) + 1;
    bn_data_num = num / BN_DEC_NUM + 1;
    bn_data = (BN_ULONG *)OPENSSL_malloc(bn_data_num * sizeof(BN_ULONG));
    buf = (char *)OPENSSL_malloc(num + 3);
    if ((buf == NULL) || (bn_data == NULL)) {
        BNerr(BN_F_BN_BN2DEC, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if ((t = BN_dup(a)) == NULL)
        goto err;

#define BUF_REMAIN (num+3 - (size_t)(p - buf))
    p = buf;
    lp = bn_data;
    if (BN_is_zero(t)) {
        *(p++) = '0';
        *(p++) = '\0';
    } else {
        if (BN_is_negative(t))
            *p++ = '-';

        while (!BN_is_zero(t)) {
            if (lp - bn_data >= bn_data_num)
                goto err;
            *lp = BN_div_word(t, BN_DEC_CONV);
            if (*lp == (BN_ULONG)-1)
                goto err;
            lp++;
        }
        lp--;
        /*
         * We now have a series of blocks, BN_DEC_NUM chars in length, where
         * the last one needs truncation. The blocks need to be reversed in
         * order.
         */
        snprintf(p, BUF_REMAIN, BN_DEC_FMT1, *lp);
        while (*p)
            p++;
        while (lp != bn_data) {
            lp--;
            snprintf(p, BUF_REMAIN, BN_DEC_FMT2, *lp);
            while (*p)
                p++;
        }
    }
    ok = 1;
 err:
    if (bn_data != NULL)
        OPENSSL_free(bn_data);
    if (t != NULL)
        BN_free(t);
    if (!ok && buf) {
        OPENSSL_free(buf);
        buf = NULL;
    }

    return (buf);
}

void ERR_put_error(int lib, int func, int reason, const char *file, int line)
{
}

void OPENSSL_cleanse(void *ptr, size_t len)
{
}

void *CRYPTO_malloc(int num, const char *file, int line)
{
	return malloc(num);
}

void CRYPTO_free(void *ptr)
{
	free(ptr);
}
