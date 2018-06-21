#!/bin/bash -x

set -e

DPDK_VERS="17.11.2"
CROSS=


case "$CROSS_ARCH" in
  "arm64")
    DPDK_TARGET="arm64-armv8a-linuxapp-"
    ;;
  "armhf")
    DPDK_TARGET="arm-armv7a-linuxapp-"
    ;;
  "i386")
    DPDK_TARGET="i686-native-linuxapp-"
    ;;
  "")
    DPDK_TARGET="x86_64-native-linuxapp-"
    DPDK_MACHINE=snb
    ;;
esac


if [ -n "$DPDK_TARGET" ] ; then
 if [ "${CC#clang}" != "${CC}" ] ; then
  DPDKCC=clang ;
 else
  DPDKCC=gcc ;
 fi
 if [ -n "$DPDK_SHARED" ] ; then
  TARGET="${DPDK_TARGET}$DPDKCC"-shared
  LIBDPDKEXT=so
  export LD_LIBRARY_PATH="`pwd`/${TARGET}:$LD_LIBRARY_PATH"
  echo $LD_LIBRARY_PATH
 else
  TARGET="${DPDK_TARGET}$DPDKCC"
  LIBDPDKEXT=a
 fi
 DPDK_TARGET="${DPDK_TARGET}gcc"
 CACHED_DPDK_VERS=`fgrep Version dpdk/pkg/dpdk.spec | cut -d " " -f 2`
 if [ ! -d dpdk -o "${CACHED_DPDK_VERS}" != "${DPDK_VERS}" ]; then
  rm -rf dpdk
  mkdir dpdk
  pushd dpdk
  git init
  git -c advice.detachedHead=false fetch -q --depth=1 http://dpdk.org/git/dpdk-stable v${DPDK_VERS}
  git checkout -f FETCH_HEAD
  popd
 fi
 if [ ! -f "dpdk/${TARGET}/usr/local/lib/libdpdk.$LIBDPDKEXT" ]; then
  pushd dpdk
  git log --oneline --decorate
  # AArch64 && ARMv7 fixup
  sed -i -e 's/40900/40800/g' lib/librte_eal/common/include/arch/arm/rte_vect.h
  sed -i -e 's/!(/!(defined(__arm__) \&\& defined(__clang__) || /g' lib/librte_eal/common/include/arch/arm/rte_byteorder.h
  sed -i -e 's/__GNUC__/defined(__arm__) \&\& defined(__clang__) || __GNUC__/' lib/librte_eal/common/include/generic/rte_byteorder.h
  sed -i -e 's,\$(CC),\0 $(EXTRA_CFLAGS),g' lib/librte_acl/Makefile
  make config T=${DPDK_TARGET} O=${TARGET}
  pushd ${TARGET}
  sed -ri 's,(CONFIG_RTE_LIBRTE_PMD_PCAP=).*,\1y,' .config
  # OCTEON TX driver includes ARM v8.1 instructions
  sed -ri 's,(CONFIG_RTE_LIBRTE_OCTEONTX_PMD=).*,\1n,' .config
  sed -ri 's,(CONFIG_RTE_LIBRTE_PMD_OCTEONTX_SSOVF=).*,\1n,' .config
  sed -ri 's,(CONFIG_RTE_LIBRTE_OCTEONTX_MEMPOOL=).*,\1n,' .config
  if test -n "${DPDK_MACHINE}" ; then
    sed -ri 's,(CONFIG_RTE_MACHINE=).*,\1"'${DPDK_MACHINE}'",' .config
  fi
  if test -n "${DPDK_SHARED}" ; then
    sed -ri 's,(CONFIG_RTE_BUILD_SHARED_LIB=).*,\1y,' .config
  fi
  if test -n "$CROSS_ARCH" ; then
    sed -ri -e 's,(CONFIG_RTE_EAL_IGB_UIO=).*,\1n,' .config
    sed -ri -e 's,(CONFIG_RTE_KNI_KMOD=).*,\1n,' .config
  fi
  sed -ri -e 's,(CONFIG_RTE_TOOLCHAIN=).*,\1"'${DPDKCC}'",' .config
  sed -ri -e '/CONFIG_RTE_TOOLCHAIN_.*/d' .config
  echo CONFIG_RTE_TOOLCHAIN_${DPDKCC^^}=y >> .config
  popd
  make build O=${TARGET} EXTRA_CFLAGS="-fPIC $DPDK_CFLAGS" CROSS="$DPDK_CROSS" CC="$CC" HOSTCC=gcc -j $(nproc)
  make install O=${TARGET} DESTDIR=${TARGET}
  rm -r ./doc ./${TARGET}/app ./${TARGET}/build
  popd
 fi
fi
