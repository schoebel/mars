#
# Makefile for MARS
#

obj-$(CONFIG_MARS)		+= mars_generic.o
obj-$(CONFIG_MARS_DUMMY)	+= mars_dummy.o
obj-$(CONFIG_MARS_IF_DEVICE)	+= mars_if_device.o
obj-$(CONFIG_MARS_DEVICE_SYNC)	+= mars_device_sync.o

obj-$(CONFIG_MARS_TEST)		+= mars_test.o

#mars-objs	:= mars_generic.o
