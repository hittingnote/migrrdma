tgt:=src/wbs_external src/migrrdma_daemon utils/prerestore

all:
	@for i in $(tgt); do \
		make -C $$i; \
		if [ $$? -ne 0 ]; then \
			exit $$?; \
		fi \
	done

.PHONY: clean
clean:
	@for i in $(tgt); do \
		make -C $$i clean; \
	done

