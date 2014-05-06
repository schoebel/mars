#
# Makefile for MARS module
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
KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$(PWD)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

config:
	$(MAKE) -C $(KDIR) M=$(PWD) config

endif
