obj-m := hook.o
PWD := $(shell pwd)
KVER := $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
all:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules
clean:
	rm -f *.ko *.o* *.mod*	Module.symvers
