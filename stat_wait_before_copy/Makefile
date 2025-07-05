src=$(wildcard *.c)
obj=$(patsubst %.c,%.o, $(src))
tgt=calculate
rmfile=$(shell ls $(obj) $(tgt) 2> /dev/null)

all: $(tgt)

$(tgt): $(obj)
	gcc $^ -lpthread -o $@

$(obj): %.o: %.c
	gcc -c $< -o $@

.PHONY: clean
clean:
ifneq ($(rmfile),)
	rm $(rmfile)
endif
