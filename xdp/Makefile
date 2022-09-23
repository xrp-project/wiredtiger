GCC = gcc
CFLAGS = -Og -g -Wall

main.out: main.o
	$(GCC) -o main.out main.o -lpthread -lwiredtiger

main.o: main.c
	$(GCC) $(CFLAGS) -c main.c -o main.o -lpthread -lwiredtiger

test_wiredtiger_internal:
	$(GCC) $(CFLAGS) -o wiredtiger_internal_test.out wiredtiger_internal_test.c

print_wt_struct_sizes:
	$(GCC) $(CFLAGS) -o print_wt_struct_sizes.out print_wt_struct_sizes.c -lwiredtiger

print_wt_bpf_struct_sizes:
	$(GCC) $(CFLAGS) -o print_wt_bpf_struct_sizes.out print_wt_bpf_struct_sizes.c

clean:
	rm *.o *.out
