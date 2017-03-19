CONTIKI_PROJECT = nyoci-plugtest

ifeq ($(CONTIKI),)
CONTIKI = ../../../../contiki
endif

NYOCI_ROOT = ../../..

ifneq ($(UIP_CONF_IPV6),)
CFLAGS += -DUIP_CONF_IPV6=$(UIP_CONF_IPV6)
endif

NYOCI_CONF_EXTRAS = 1

#VERBOSE_DEBUG = 0

include $(NYOCI_ROOT)/contiki-src/Makefile.nyoci

CONTIKI_SOURCEFILES += plugtest-server.c
PROJECTDIRS += $(NYOCI_ROOT)/src/plugtest

ifeq ($(TARGET),avr-raven)
#APPS += raven-webserver
APPS += raven-lcd-interface
endif

CLEAN += *.hex *.elf symbols.c symbols.h

all: $(CONTIKI_PROJECT)

include $(CONTIKI)/Makefile.include

ifeq ($(CC),sdcc)
CFLAGS += --disable-warning 115
endif

burn: $(CONTIKI_PROJECT).u

burn-eeprom: $(CONTIKI_PROJECT).u-eep
