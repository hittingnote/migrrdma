#include "rdma_footprint.h"

static inline int up_to_pow_two(int n) {
	int tmp = n;
	while(tmp & (tmp - 1))
		tmp = (tmp & (tmp - 1));
	
	if(n > tmp)
		return 2*tmp;
	else
		return tmp;
}

static void *expand_buf(void *buf, size_t orig_size, size_t new_size) {
	void *buf_tmp = NULL;

	if(up_to_pow_two(new_size) <= up_to_pow_two(orig_size))
		return buf;
	
	buf_tmp = kzalloc(up_to_pow_two(new_size), GFP_KERNEL);
	if(!buf_tmp) {
		if(buf)
			kfree(buf);
		return NULL;
	}

	memset(buf_tmp, 0, up_to_pow_two(new_size));
	memcpy(buf_tmp, buf, up_to_pow_two(orig_size));
	if(buf)
		kfree(buf);
	buf = buf_tmp;
	return buf;
}

static void *shrink_buf(void *buf, size_t *this_size, loff_t *off, int *err) {
	void *buf_tmp = NULL;
	size_t shrink_size;
	*err = 0;

	if(up_to_pow_two(*this_size - *off) >= up_to_pow_two(*this_size)) {
		return buf;
	}

	shrink_size = *this_size - up_to_pow_two(*this_size - *off);
	if(up_to_pow_two(*this_size - *off)) {
		buf_tmp = kzalloc(up_to_pow_two(*this_size - *off), GFP_KERNEL);
		if(!buf_tmp) {
			if(buf)
				kfree(buf);
			*err = -ENOMEM;
			return NULL;
		}
	}
	else {
		buf_tmp = NULL;
	}

	memset(buf_tmp, 0, up_to_pow_two(*this_size - *off));
	memcpy(buf_tmp, buf + shrink_size, up_to_pow_two(*this_size - *off));
	*off = *off - shrink_size;
	*this_size = *this_size - shrink_size;

	if(buf)
		kfree(buf);
	buf = buf_tmp;
	return buf;
}

ssize_t channel_to_proc_write(void **channel_buf, size_t *orig_size,
					const char __user *buf, size_t size) {
	int err;

	*channel_buf = expand_buf(*channel_buf, *orig_size, *orig_size + size);
	if(!(*channel_buf)) {
		*orig_size = 0;
		return -ENOMEM;
	}

	err = copy_from_user(*channel_buf + *orig_size, buf, size);
	if(err) {
		kfree(*channel_buf);
		*channel_buf = NULL;
		*orig_size = 0;
		return err;
	}
	
	*orig_size = *orig_size + size;
	return size;
}

ssize_t channel_from_frm_read(void **channel_buf, size_t *orig_size,
					char __user *buf, size_t size, loff_t *off) {
	int err;

	printk(KERN_NOTICE "In %s(%d): orig_size: %d, off: %d\n", __FILE__, __LINE__,
							*orig_size, *off);

	err = copy_to_user(buf, *channel_buf + *off, size);
	if(err) {
		kfree(*channel_buf);
		*channel_buf = NULL;
		*off = 0;
		*orig_size = 0;
		return err;
	}

	*off = *off + size;
	*channel_buf = shrink_buf(*channel_buf, orig_size, off, &err);
	if(err) {
		*off = 0;
		*orig_size = 0;
		return err;
	}

	return size;
}
