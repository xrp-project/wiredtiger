WT_DIR ?= ..
XRP_INC ?= /mydata/wtx/include
CC ?= gcc
CFLAGS = -O2 -g -Wall -I$(WT_DIR) -I$(XRP_INC)
LDFLAGS = -L$(WT_DIR)/.libs -Wl,-rpath,$(WT_DIR)/.libs
LDLIBS = -lwiredtiger -lpthread -ldl

all: create_db user_lookup xrp_lookup wt_read rw_bench

wt_read: wt_read.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

rw_bench: rw_bench.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

create_db: create_db.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

user_lookup: user_lookup.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

xrp_lookup: xrp_lookup.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS) -lbpf

clean:
	rm -f create_db user_lookup xrp_lookup

bpfof_lookup: bpfof_lookup.c kv.h
	$(CC) $(CFLAGS) -I.. -I$(XRP_INC) -o $@ bpfof_lookup.c $(LDFLAGS) -lwiredtiger -lpthread -ldl -lbpf
