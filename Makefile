#
# Makefile for MARS
#

obj-$(CONFIG_MARS)		+= brick.o brick_mem.o \
				   mars_generic.o sy_old/sy_generic.o \
				   mars_net.o sy_old/sy_net.o \
				   sy_old/mars_proc.o
obj-$(CONFIG_MARS_DUMMY)	+= mars_dummy.o
obj-$(CONFIG_MARS_CHECK)	+= mars_check.o
obj-$(CONFIG_MARS_IF)		+= mars_if.o
obj-$(CONFIG_MARS_BIO)		+= mars_bio.o
obj-$(CONFIG_MARS_AIO)		+= mars_aio.o
obj-$(CONFIG_MARS_SIO)		+= mars_sio.o
obj-$(CONFIG_MARS_BUF)		+= mars_buf.o
obj-$(CONFIG_MARS_USEBUF)	+= mars_usebuf.o
obj-$(CONFIG_MARS_TRANS_LOGGER)	+= mars_trans_logger.o lib_log.o
obj-$(CONFIG_MARS_SERVER)	+= mars_server.o
obj-$(CONFIG_MARS_CLIENT)	+= mars_client.o
obj-$(CONFIG_MARS_COPY)		+= mars_copy.o

obj-$(CONFIG_MARS_LIGHT)	+= sy_old/mars_light.o

#mars-objs	:= mars_generic.o

ifdef CONFIG_DEBUG_KERNEL
KBUILD_CFLAGS += -fno-inline-functions -fno-inline-small-functions -fno-inline-functions-called-once
endif
