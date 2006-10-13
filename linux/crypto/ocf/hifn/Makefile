
ifdef obj
my_inc_base = $(obj)
else
my_inc_base = .
O_TARGET := ocfdrv.o
endif

obj-$(CONFIG_OCF_HIFN)       += $(obj-base)hifn7751.o
obj-$(CONFIG_OCF_HIFNHIPP)   += $(obj-base)hifnHIPP.o

EXTRA_CFLAGS += -I$(my_inc_base)/.

