obj-m += my-module.o

PWD := $(CURDIR)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load: all
	sudo insmod my-module.ko
	sudo chmod a+rw /proc/my_module

unload:
	sudo rmmod my-module

user: get-struct.c
	gcc -o get-struct get-struct.c	
