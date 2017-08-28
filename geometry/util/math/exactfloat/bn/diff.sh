#!/bin/bash

if [ -z "${1}" ]; then
    echo usage: diff.sh openssl-src-dir
    exit 1
fi

diff -c ${1}/crypto/bn/bn_asm.c bn_asm.c
diff -c ${1}/crypto/bn/bn_ctx.c bn_ctx.c
diff -c ${1}/crypto/bn/bn_mul.c bn_mul.c
diff -c ${1}/crypto/bn/bn_sqr.c bn_sqr.c

diff -c ${1}/crypto/bn/bn.h bn.h
diff -c ${1}/crypto/bn/bn_lcl.h bn_lcl.h
diff -c ${1}/crypto/crypto.h crypto.h
diff -c ${1}/e_os2.h e_os2.h
diff -c ${1}/crypto/err/err.h err.h
diff -c ${1}/crypto/opensslconf.h opensslconf.h
diff -c ${1}/crypto/opensslv.h opensslv.h
diff -c ${1}/crypto/ossl_typ.h ossl_typ.h
diff -c ${1}/crypto/stack/safestack.h safestack.h
diff -c ${1}/crypto/stack/stack.h stack.h
