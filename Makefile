utils:=init_proc migrrdma_daemon prerestore rdma_plugin fork stat_wait_before_copy

all:
	@for i in $(utils); do \
		make -C $$i; \
	done

.PHONY: clean
clean:
	@for i in $(utils); do \
		make -C $$i clean; \
	done

