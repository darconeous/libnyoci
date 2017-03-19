CONTIKI_PROJECT = nyoci-simple

ifeq ($(CONTIKI),)
CONTIKI = ../../../../contiki
endif

NYOCI_ROOT = ../../..

NYOCI_CONF_EXTRAS = 0
#VERBOSE_DEBUG = 0

ifneq ($(UIP_CONF_IPV6),)
CFLAGS += -DUIP_CONF_IPV6=$(UIP_CONF_IPV6)
endif

include $(NYOCI_ROOT)/contiki-src/Makefile.nyoci

CLEAN += *.hex *.elf symbols.c symbols.h

all: $(CONTIKI_PROJECT)

include $(CONTIKI)/Makefile.include

ifeq ($(CC),sdcc)
CFLAGS += --disable-warning 115
endif

burn: $(CONTIKI_PROJECT).u

burn-eeprom: $(CONTIKI_PROJECT).u-eep
