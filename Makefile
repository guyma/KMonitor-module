obj-m += KMonitor.o

all:
	make  -C  /lib/modules/`uname -r`/build M=$(PWD) modules EXTRA_CFLAGS="-g"
clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean
