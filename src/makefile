obj-m += rootkit.o
obj-m += 

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	mkdir -p ../build
	mv *.ko *.o *.mod.c .*.cmd Module.symvers modules.order *.mod ../build/
	insmod ../build/rootkit.ko
	dmesg

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf ../build
	rmmod rootkit
