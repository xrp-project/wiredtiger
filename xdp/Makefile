GCC = gcc
CFLAGS = -Og -g -Wall

main.out: main.o
	$(GCC) -o main.out main.o -lpthread -lwiredtiger

main.o: main.c
	$(GCC) $(CFLAGS) -c main.c -o main.o -lpthread -lwiredtiger

test_wiredtiger_internal:
	$(GCC) $(CFLAGS) wiredtiger_internal_test.c

clean:
	rm *.o *.out
