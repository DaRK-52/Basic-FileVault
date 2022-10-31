obj-m := basic_filevault.o
basic_filevault-objs := main.o hook.o syscalltable.o
PWD := $(shell pwd)
KVER := $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
all:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules
clean:
	rm -f *.ko *.o* *.mod*	Module.symvers
