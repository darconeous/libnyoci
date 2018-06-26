LibNyoci — A Full-Featured Embedded CoAP Stack
==============================================

LibNyoci is a highly-configurable CoAP stack which is suitable for a wide
range of embedded devices, from bare-metal sensor nodes with kilobytes of RAM
to Linux-based devices with megabytes of RAM.

LibNyoci was spun off from the [SMCP][] project in late March of 2017.

Features include:

 * Supports [RFC7252][1]
 * Fully asynchronous I/O
 * Supports both BSD sockets and [µIP][2]
 * Sending and receiving asynchronous CoAP responses
 * Observing resources and offering observable resources
 * Retransmission of confirmable transactions
 * [Experimental support for DTLS](https://github.com/darconeous/libnyoci/issues/35)

The package also includes `nyocictl`, a powerful command line tool for browsing
and configuring CoAP nodes.

LibNyoci is currently working toward a v1.0 API. Until v1.0 is released, all APIs
are subject to change.

[SMCP]: https://github.com/darconeous/smcp
[1]: http://tools.ietf.org/html/7252
[2]: http://en.wikipedia.org/wiki/UIP_%28micro_IP%29
[3]: http://tools.ietf.org/html/rfc7390

## Getting Help ##

If you are having trouble with LibNyoci, you can either [file an issue on
github](https://github.com/darconeous/libnyoci/issues/new) or join the
official [LibNyoci Developers mailing list][libnyoci-dev] and ask your
question there.

### Mailing Lists ###

* [LibNyoci Announcements][libnyoci-announce] <libnyoci-announce@googlegroups.com>
  Release announcements and security notices. Low traffic.
* [LibNyoci Developers][libnyoci-dev] <libnyoci-dev@googlegroups.com>
  Developer discussion about LibNyoci.

[libnyoci-announce]: https://groups.google.com/group/libnyoci-announce
[libnyoci-dev]: https://groups.google.com/group/libnyoci-dev

## Getting, building, and installing via Git ##

First:

	$ git clone git://github.com/darconeous/libnyoci.git
	$ cd libnyoci

To just build the latest tagged stable release:

	$ git checkout full/latest-release
	$ ./configure
	$ make
	$ sudo make install

For bleeding-edge:

	$ git checkout master
	$ git archive origin/autoconf/master | tar xvm
	  # Next line is a work-around for timestamp problems
	$ touch aclocal.m4 && touch configure && touch `find . -name '*.in'`
	$ ./configure
	$ make
	$ sudo make install

## Getting, building, and installing from an archive ##

	$ curl https://github.com/darconeous/libnyoci/archive/full/latest-release.zip > latest-release.zip
	$ unzip latest-release.zip
	$ cd nyoci-latest-release
	$ ./configure
	$ make
	$ sudo make install

## Installing via Homebrew on OS X ##

To get the "latest-release":

	$ brew tap darconeous/embedded
	$ brew install libnyoci

To get the bleeding-edge release:

	$ brew tap darconeous/embedded
	$ brew install libnyoci --HEAD

## Getting Started ##

The best way to get started is to have a look at some example code
which uses LibNyoci. There are several included examples:

* `examples/example-1.c` - Shows how to respond to a request.
* `examples/example-2.c` - Shows how to respond to a request for a specific resource.
* `examples/example-3.c` - Shows how to use the node router.
* `examples/example-4.c` - Shows how to make resources observable.

Additionally, there is the plugtest server and client, which can be found
in `src/plugtest`.

The Contiki version of the plugtest uses the last two files. You can find
the Contiki version at `contiki-src/examples/nyoci-plugtest/`.

## Configurability ##

One of the goals of LibNyoci is to implent a full-featured CoAP library, but
most embedded applications don't need all of these capabilities. Because of this,
LibNyoci is designed so that you can individually enable or disable features
depending on your needs (See `src/libnyoci/nyoci-config.h.in`).

For example, LibNyoci has the ability to have more than once instance, but embedded
platforms will never need more than one. Passing around a reference to a
global variable that will never change is wasteful, so when compiled with
`NYOCI_SINGLETON` turned on, we transparently (via some preprocessor magic) ignore
the reference to the LibNyoci instance from all of the functions that take it.
This makes it easy to use the same codebase for both embedded and non-embedded
applications. There are other configuration options for doing things like
limiting `malloc()` usage, avoiding use of `printf()` (and variants),
enabling/disabling observing, etc.

## Contiki Support ##

LibNyoci supports [Contiki](http://contiki-os.org/) (albeit a rather old version).
To build the Contiki examples, just make sure that the `CONTIKI` environment
variable is set point to your Contiki root, like so:

	$ cd contiki-src/examples/nyoci-simple
	$ make CONTIKI=~/Projects/contiki TARGET=minimal-net

## API Documentation ##

You can find an online version of the API documentation here:
<http://darconeous.github.com/libnyoci/doc/html/>

## `nyocictl` ##

`nyocictl` is a command-line interface for browsing, observing, and
interacting with CoAP devices. It is, for the most part, self-documenting:
just type in `nyocictl help`. You can run individual commands directly from
the command line when invoking `nyocictl` or you can invoke with no
arguments and you will enter the nyocictl shell (CLI). The shell environment
allows you to use familiar unix commands like `ls`, `cd`, and `cat`. The
CLI supports quoting and tab-completion of resource names, which is
incredibly handy.

Here are a few examples of how you can use it:

### GET a resource ###

	$ nyocictl get coap://coap.me/large

### Listing the contents of a resource ###

	$ nyocictl ls coap://coap.me/.well-known/core

### PUT a resource and show parsed response headers ###

	$ nyocictl put -i coap://coap.me/test "Testing out nyocictl's PUT command"

### Observe a resource for changes ###

	$ nyocictl observe coap://vs0.inf.ethz.ch/obs

## Plugtests ##

`nyoci-plugtest-server` implements some of the ESTI plugtests for CoAP.

### List of Public Test Servers ###

These servers run a subset of the plugtest suite:

 * <coap://coap.me/>
 * <coap://vs0.inf.ethz.ch/>

These are other publically-accessable example/test servers:

 * <coap://leshan.eclipse.org>/<coaps://leshan.eclipse.org>
 * <coap://californium.eclipse.org>/<coaps://californium.eclipse.org>

## Authors and Significant Contributors ##

 * [Robert Quattlebaum](https://github.com/darconeous)

### Special Thanks ###

 * [Paulo Brizolara](https://github.com/paulobrizolara), for help with IPv4 multicast support.
