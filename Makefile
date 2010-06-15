#
# Makefile for MARS
#

obj-$(CONFIG_MARS)		+= mars_generic.o
obj-$(CONFIG_MARS_DUMMY)	+= mars_dummy.o
obj-$(CONFIG_MARS_IF_DEVICE)	+= mars_if_device.o
obj-$(CONFIG_MARS_DEVICE_SIO)	+= mars_device_sio.o

obj-$(CONFIG_MARS_TEST)		+= mars_test.o

#mars-objs	:= mars_generic.o
