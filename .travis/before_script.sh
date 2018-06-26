#!/bin/sh

die() {
	echo " *** ERROR: " $*
	exit 1
}

set -x

SUPPORTED_CONTIKI_REF=${SUPPORTED_CONTIKI_REF-1d69099}

if [ $BUILD_PLATFORM = contiki ]
then
	git clone git://github.com/contiki-os/contiki.git || die
	cd contiki || die
	git checkout ${SUPPORTED_CONTIKI_REF} || die
	cd .. || die
fi

exit 0
