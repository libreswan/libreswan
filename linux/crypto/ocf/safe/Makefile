
ifdef obj
my_inc_base = $(obj)
else
my_inc_base = .
O_TARGET := safe.o
endif

obj-$(CONFIG_OCF_SAFE)       += $(obj-base)safe.o


EXTRA_CFLAGS += -I$(my_inc_base)/.

