all: target1 target2 target3 target4 target5
	chmod og-rwx *
	echo Done

target1: target1.c
	gcc -g target1.c -o target1

target2: target2.c stackSetup.c
	gcc -c -g target2.c -o target2.o
	objcopy --redefine-sym main=lab_main target2.o
	gcc -g target2.o stackSetup.c -o target2 -lpthread
	rm target2.o

target3: target3.c stackSetup.c
	gcc -c -g target3.c -o target3.o
	objcopy --redefine-sym main=lab_main target3.o
	gcc -g target3.o stackSetup.c -o target3 -lpthread
	rm target3.o

target4: target4.c stackSetup.c tmalloc.h tmalloc.c
	gcc -c -g target4.c -o target4.o
	objcopy --redefine-sym main=lab_main target4.o
	gcc -g target4.o stackSetup.c tmalloc.c -o target4 -lpthread
	rm target4.o

target5: target5.c stackSetup.c
	gcc -c -g target5.c -o target5.o
	objcopy --redefine-sym main=lab_main target5.o
	gcc -g target5.o stackSetup.c -o target5 -lpthread
	rm target5.o

clean:
	rm target1 target2 target3 target4 target5
