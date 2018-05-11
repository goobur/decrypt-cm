cmdecrypt: main.o miniz.o
	gcc -o cmdecrypt main.o miniz.o

main.o: main.c miniz.h
	gcc -c main.c

miniz.o: miniz.c miniz.h
	gcc -c miniz.c