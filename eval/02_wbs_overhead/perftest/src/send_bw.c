/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies Ltd.  All rights reserved.
 * Copyright (c) 2009 HNR Consulting.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "perftest_parameters.h"
#include "perftest_resources.h"
#include "multicast_resources.h"
#include "perftest_communication.h"

/******************************************************************************
 *
 ******************************************************************************/
int main(int argc, char *argv[])
{
	struct ibv_device		*ib_dev = NULL;
	struct pingpong_context  	ctx;
	struct pingpong_dest	 	*my_dest  = NULL;
	struct pingpong_dest		*rem_dest = NULL;
	struct perftest_parameters  	user_param;
	struct perftest_comm		*user_comm = NULL;
	struct bw_report_data		my_bw_rep;
	char						**servername_list = NULL;
	int                      	ret_parser, i = 0;

	/* init default values to user's parameters */
	memset(&ctx, 0,sizeof(struct pingpong_context));
	memset(&user_param, 0 , sizeof(struct perftest_parameters));

	user_param.verb    = SEND;
	user_param.tst     = BW;
	strncpy(user_param.version, VERSION, sizeof(user_param.version));

	/* Configure the parameters values according to user arguments or defalut values. */
	ret_parser = parser(&user_param,argv,argc);
	if (ret_parser) {
		if (ret_parser != VERSION_EXIT && ret_parser != HELP_EXIT)
			fprintf(stderr," Parser function exited with Error\n");
		goto return_error;
	}

	user_param.num_of_qps = argc - optind;
	MAIN_ALLOC(servername_list, char*, user_param.num_of_qps, return_error);
	memset(servername_list, 0, sizeof(char*)*user_param.num_of_qps);
	for (i = 0; i < user_param.num_of_qps; i++) {
		servername_list[i] = argv[optind + i];
	}

/* Finding the IB device selected (or defalut if no selected). */
	ib_dev = ctx_find_dev(&user_param.ib_devname);
	if (!ib_dev) {
		fprintf(stderr," Unable to find the Infiniband/RoCE device\n");
		goto return_error;
	}

	/* Getting the relevant context from the device */
	ctx.context = ctx_open_device(ib_dev, &user_param);
	if (!ctx.context) {
		fprintf(stderr, " Couldn't get context for the device\n");
		goto free_devname;
	}

	/* Verify user parameters that require the device context,
	 * the function will print the relevent error info. */
	if (verify_params_with_device_context(ctx.context, &user_param)) {
		fprintf(stderr, " Couldn't get context for the device\n");
		goto free_devname;
	}

	/* See if link type is valid and supported. */
	if (check_link(ctx.context,&user_param)) {
		fprintf(stderr, " Couldn't get context for the device\n");
		goto free_devname;
	}

	MAIN_ALLOC(user_comm, struct perftest_comm, user_param.num_of_qps, return_error);
	memset(user_comm, 0, sizeof(struct perftest_comm)*user_param.num_of_qps);
	MAIN_ALLOC(my_dest, struct pingpong_dest, user_param.num_of_qps, return_error);
	memset(my_dest, 0, sizeof(struct pingpong_dest)*user_param.num_of_qps);
	MAIN_ALLOC(rem_dest, struct pingpong_dest, user_param.num_of_qps, free_my_dest);
	memset(rem_dest, 0, sizeof(struct pingpong_dest)*user_param.num_of_qps);

	int port_base = user_param.port;
	for (i = 0; i < user_param.num_of_qps; i++) {
		user_param.servername = servername_list[i];		
		user_param.port = port_base + i;

		printf("%s\n", user_param.servername);
		/* copy the relevant user parameters to the comm struct + creating rdma_cm resources. */
		if (create_comm_struct(&user_comm[i],&user_param)) {
			fprintf(stderr," Unable to create RDMA_CM resources\n");
			goto free_devname;
		}

		/* Initialize the connection and print the local data. */
		if (establish_connection(&user_comm[i])) {
			fprintf(stderr," Unable to init the socket connection\n");
			dealloc_comm_struct(&user_comm[i],&user_param);
			goto free_devname;
		}

		exchange_versions(&user_comm[i], &user_param);
		check_version_compatibility(&user_param);
		check_sys_data(&user_comm[i], &user_param);

		/* See if MTU is valid and supported. */
		if (check_mtu(ctx.context,&user_param, &user_comm[i])) {
			fprintf(stderr, " Couldn't get context for the device\n");
			dealloc_comm_struct(&user_comm[i],&user_param);
			return FAILURE;
		}		
	}

	if (user_param.output == FULL_VERBOSITY && user_param.machine == SERVER) {
		printf("\n************************************\n");
		printf("* Waiting for client to connect... *\n");
		printf("************************************\n");
	}

	/* Allocating arrays needed for the test. */
	if (alloc_ctx(&ctx,&user_param)){
		fprintf(stderr, "Couldn't allocate context\n");
		goto free_mem;
	}

	/* create all the basic IB resources (data buffer, PD, MR, CQ and events channel) */
	if (ctx_init(&ctx, &user_param)) {
		fprintf(stderr, " Couldn't create IB resources\n");
		dealloc_ctx(&ctx, &user_param);
		goto free_mem;
	}

	/* Set up the Connection. */
	if (set_up_connection(&ctx,&user_param,my_dest)) {
		fprintf(stderr," Unable to set up my IB connection parameters\n");
		return FAILURE;
	}

	/* Print basic test information. */
	ctx_print_test_info(&user_param);

	for (i=0; i < user_param.num_of_qps; i++) {
		/* shaking hands and gather the other side info. */
		if (ctx_hand_shake(&user_comm[i],&my_dest[i],&rem_dest[i])) {
			fprintf(stderr,"Failed to exchange data between server and clients\n");
			goto destroy_context;
		}

		if (ctx_check_gid_compatibility(&my_dest[i], &rem_dest[i])) {
			fprintf(stderr,"\n Found Incompatibility issue with GID types.\n");
			fprintf(stderr," Please Try to use a different IP version.\n\n");
			goto destroy_context;
		}
	}
	
	/* Prepare IB resources for rtr/rts. */
	if (ctx_connect(&ctx,rem_dest,&user_param,my_dest)) {
		fprintf(stderr," Unable to Connect the HCA's through the link\n");
		goto destroy_context;
	}

	for (i=0; i < user_param.num_of_qps; i++) {
		/* shaking hands and gather the other side info. */
		if (ctx_hand_shake(&user_comm[i],&my_dest[i],&rem_dest[i])) {
			fprintf(stderr,"Failed to exchange data between server and clients\n");
			goto destroy_context;
		}

		/* Print this machine QP information */
		ctx_print_pingpong_data(&my_dest[i],&user_comm[i]);

		user_comm[i].rdma_params->side = REMOTE;

		if (ctx_hand_shake(&user_comm[i],&my_dest[i],&rem_dest[i])) {
			fprintf(stderr," Failed to exchange data between server and clients\n");
			goto destroy_context;
		}

		ctx_print_pingpong_data(&rem_dest[i],&user_comm[i]);
	}
	
	if (user_param.output == FULL_VERBOSITY) {
		if (user_param.report_per_port) {
			printf(RESULT_LINE_PER_PORT);
			printf((user_param.report_fmt == MBS ? RESULT_FMT_PER_PORT : RESULT_FMT_G_PER_PORT));
		}
		else {
			printf(RESULT_LINE);
			printf((user_param.report_fmt == MBS ? RESULT_FMT : RESULT_FMT_G));
		}
		printf((user_param.cpu_util_data.enable ? RESULT_EXT_CPU_UTIL : RESULT_EXT));
	}

	if (user_param.machine == CLIENT)
		ctx_set_send_wqes(&ctx,&user_param,rem_dest);
	if (user_param.machine == SERVER) {
		if (ctx_set_recv_wqes(&ctx,&user_param)) {
			fprintf(stderr," Failed to post receive recv_wqes\n");
			goto free_mem;
		}
	}

	for (i=0; i < user_param.num_of_qps; i++) {
		if (ctx_hand_shake(&user_comm[i],&my_dest[i],&rem_dest[i])) {
			fprintf(stderr,"Failed to exchange data between server and clients\n");
			goto free_mem;
		}
	}

	if (user_param.machine == CLIENT) {
		if(run_iter_bw(&ctx,&user_param)) {
			goto free_mem;
		}
	} else if(run_iter_bw_server(&ctx,&user_param)) {
			goto free_mem;
	}

	print_report_bw(&user_param,&my_bw_rep);

	if (user_param.output == FULL_VERBOSITY) {
		if (user_param.report_per_port)
			printf(RESULT_LINE_PER_PORT);
		else
			printf(RESULT_LINE);
	}

	for (i=0; i < user_param.num_of_qps; i++) {
		if (ctx_close_connection(&user_comm[i],&my_dest[i],&rem_dest[i])) {
			fprintf(stderr," Failed to close connection between server and client\n");
			fprintf(stderr," Trying to close this side resources\n");
		}
	}

	/* Destroy all test resources, including Mcast if exists */
	if (destroy_ctx(&ctx,&user_param)) {
		fprintf(stderr,"Couldn't destroy all SEND resources\n");
		goto return_error;
	}
	
	free(my_dest);
	free(rem_dest);
	free(user_param.ib_devname);
	for (i=0; i < user_param.num_of_qps; i++) {
		free(user_comm[i].rdma_params);
	}

	return SUCCESS;

destroy_context:
	if (destroy_ctx(&ctx,&user_param))
		fprintf(stderr, "Failed to destroy resources\n");
free_mem:
	free(rem_dest);
free_my_dest:
	free(my_dest);
free_devname:
	free(user_param.ib_devname);
return_error:
	return FAILURE;
}