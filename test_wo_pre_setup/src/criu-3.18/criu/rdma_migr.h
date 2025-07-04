#ifndef __RDMA_NOTIFY_H__
#define __RDMA_NOTIFY_H__

#include <stdio.h>
#include <infiniband/verbs.h>
#include "include/restorer.h"
#include "include/util.h"

extern int num_devices;
extern struct ibv_device **ibv_device_list;

extern int is_rdma_dev(unsigned long st_rdev);
extern int dump_rdma(pid_t pid, char *img_dir_path);
extern int restore_rdma(pid_t pid, char *img_dir_path);
extern int prepare_for_partners_restore(pid_t pid);

#define is_rdma_event_fd(link)								\
	is_anon_link_type(link, "[infinibandevent]")

extern int add_rdma_vma_node(pid_t pid);
extern int add_one_rdma_vma_node(unsigned long long start, unsigned long long end);
extern int check_rdma_vma(unsigned long long start, unsigned long long end);
extern struct unmapped_node *get_rdma_unmapped_node(int *pn_unmapped, int *err);
extern int add_update_node(void *ptr, size_t size, void *content_p);
extern size_t get_update_node_size(int *n_node);
extern void copy_update_nodes(void *to);
extern size_t get_total_content_size(void);
extern int load_qp_callback(struct ibv_qp *orig_qp, void *replay_fn);
extern int load_srq_callback(struct ibv_srq *srq, void *replay_fn, int head, int tail);
extern size_t get_qp_replay_size(int *n_node);
extern void copy_qp_replay_nodes(void *to);
extern size_t get_send_msg_meta_size(int *pn_msgs);
extern size_t get_send_msg_size(void);
extern void copy_send_msg_meta(void *to);
extern size_t get_srq_replay_size(int *n);
extern void copy_srq_replay_nodes(void *to);

extern int stop_and_copy_update_core(void *clone_arg);
extern int stop_and_copy_update_state(struct pstree_item *current,
				void *clone_arg);

extern int insert_id_fe_map_entry(uint32_t id, void *ptr);
extern void *get_fe_ptr_from_id(uint32_t id);

extern int rdma_plugin_main(int argc, char *argv[]);

#endif
