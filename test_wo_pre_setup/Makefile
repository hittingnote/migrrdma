utils:=fullrestore rdma_plugin

all:
	@for i in $(utils); do \
		make -C $$i; \
	done

.PHONY: clean
clean:
	@for i in $(utils); do \
		make -C $$i clean; \
	done

