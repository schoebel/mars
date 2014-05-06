#
# Makefile for out-of-tree build of MARS module
#
#
# By Benjamin Kübler <benjamin.kuebler@1und1.de>
#
# usage make [ KDIR =/path/to/kernel/source ]

ifneq ($(KERNELRELEASE),)

# in-tree-build process
include Kbuild

else
# out-of-tree-build process

MARSSRC := $(shell pwd)
DESTDIR ?= /
KDIR ?= /lib/modules/`uname -r`/build

.PHONY: greeting install default clean config

default: greeting 
	$(MAKE) -C $(KDIR) M=$(PWD)

greeting:
	@echo "Building MARS Module again: KDIR=$(KDIR)" ;
	@if ! test -e $(KDIR)/Makefile ; then \
		echo -e "Sorry, kernel makefile not found. You need to tell me a correct KDIR!\n" ; \
		false; \
	fi

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

config:
	$(MAKE) -C $(KDIR) M=$(PWD) config

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
endif
