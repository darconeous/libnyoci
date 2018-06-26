#!/bin/sh
die() {
	echo " *** ERROR: " $*
	exit 1
}

set -x

# This should already be handled by the .travis.yml file.
#[ $TRAVIS_OS_NAME != linux ] || {
#	sudo apt-get -y update || die
#	sudo apt-get -y install bsdtar autoconf-archive automake autoconf || die
#}

[ $TRAVIS_OS_NAME != osx ] || {
	brew install autoconf-archive || die
}
