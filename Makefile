CC = g++
all: fend

fend: fend.o utility.o
	$(CC) fend.o utility.o -o fend

fend.o: fend.cpp
	$(CC) -c fend.cpp 

utility.o: utility.cpp
	$(CC) -c utility.cpp
