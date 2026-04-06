src=$(wildcard *.c)
obj=$(patsubst %.c,%.o, $(src))
tgt=wbs
rmfile=$(shell ls $(obj) $(tgt) 2> /dev/null)

all: $(tgt)

$(tgt): $(obj)
	gcc $^ -L ../rdma-core-54mlnx1/build/lib/ -lpthread -o $@

$(obj): %.o: %.c
	gcc -c -I ../rdma-core-54mlnx1/build/include/ $< -o $@

.PHONY: clean
clean:
ifneq ($(rmfile),)
	rm $(rmfile)
endif
