#!/bin/sh

# check input parameter
#if [ ${#} -ne 4 ]; then
#fi

# gcc path
CC1PLUS=`${1}gcc -print-prog-name=cc1plus`
CC1PLUS_DIR=`echo $(dirname ${CC1PLUS})`
STRIP=${1}strip

FSLIBDIR=${2}/lib
CCLIBCDIR=${CC1PLUS_DIR}/../../../../arm-linux-gnueabihf/libc/lib/
CCLIBDIR=${CC1PLUS_DIR}/../../../../arm-linux-gnueabihf/lib/
DBGLIBDIR=${CC1PLUS_DIR}/../../../../arm-linux-gnueabihf/sysroot/usr/

echo "copy libc(so) to rootfs"

rm -f ${FSLIBDIR}/*.a
rm -f ${FSLIBDIR}/*.so
rm -f ${FSLIBDIR}/*.so.*
rm -f ${FSLIBDIR}/*.spec
rm -f ${FSLIBDIR}/*.o

cp -df ${CCLIBCDIR}/* ${FSLIBDIR}/

echo "copy lib(so) to rootfs"
cp -df ${CCLIBDIR}/* ${FSLIBDIR}/

echo "copy debug lib(so) to rootfs"
cp -df ${DBGLIBDIR}/lib/libncurses.so* ${FSLIBDIR}/

#cp -df ${CCLIBDIR}/libstdc++.so.* ${FSLIBDIR}/

rm -f ${FSLIBDIR}/*.a
rm -f ${FSLIBDIR}/*.spec
rm -f ${FSLIBDIR}/*.o
rm -f ${FSLIBDIR}/libgfortran*

$STRIP ${FSLIBDIR}/*.so
$STRIP ${FSLIBDIR}/*.so.*

# copy gdb, gdbserver , lsz, lrz
cp -f ${DBGLIBDIR}/bin/gdb ${FSLIBDIR}/../usr/xsbin
cp -f ${DBGLIBDIR}/bin/gdbserver ${FSLIBDIR}/../usr/xsbin
cp -f ${DBGLIBDIR}/bin/rz ${FSLIBDIR}/../usr/xsbin
cp -f ${DBGLIBDIR}/bin/sz ${FSLIBDIR}/../usr/xsbin

echo "done"
