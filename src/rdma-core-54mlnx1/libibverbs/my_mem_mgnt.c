#define _GNU_SOURCE
#include "driver.h"
#include "sys/mman.h"

#define BLOCK_LOG					16
#define BLOCK_SZ					(1UL << 16)
#define BLOCK_MASK					(~(BLOCK_SZ - 1))

static inline size_t block_aligned_up(size_t size) {
	return (size & BLOCK_MASK) + ((!!(size & (~BLOCK_MASK))) << 16);
}

static void *start_addr = NULL;
static off_t offset = 0;
static size_t alloc_size = 0;

void free_all_my_memory(void) {
	munmap(start_addr, alloc_size);
	start_addr = NULL;
	offset = 0;
	alloc_size = 0;
}

void *my_malloc(size_t size) {
	void *ret;

	if(offset + size > alloc_size) {
		/* alloc new one, or expand the existing one */
		if(!start_addr) {
			start_addr = mmap(NULL, 16777216 * 64, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
							-1, 0);
			if(start_addr == MAP_FAILED)
				return NULL;
			alloc_size = 16777216 * 64;
		}
		else {
			void *tmp_addr = mremap(start_addr, alloc_size,
						block_aligned_up(offset + size), 0);
			if(tmp_addr == MAP_FAILED || tmp_addr != start_addr)
				return NULL;
			alloc_size = block_aligned_up(offset + size);
		}
	}

	ret = start_addr + offset;
	offset += size;

	return ret;
}
