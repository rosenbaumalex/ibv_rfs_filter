/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
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
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#include <infiniband/verbs.h>

#define PORT_NUM             1
#define RQ_NUM_DESC          32  /* must have some minimum so RQ is created for flow steering command */
#define SQ_NUM_DESC          32  /* minimal send queue, although not used */
#define UDP_PORT_DEFAULT     11111

// printf formating when IP is in network byte ordering (for LITTLE_ENDIAN)
#define NIPQUAD(ip)         (uint8_t)((ip)&0xff), (uint8_t)(((ip)>>8)&0xff),(uint8_t)(((ip)>>16)&0xff),(uint8_t)(((ip)>>24)&0xff)

// Creates multicast MAC from multicast IP
// void create_multicast_mac_from_ip(uint8_t (& mc_mac) [6], in_addr_t ip)
void create_multicast_mac_from_ip(unsigned char* mc_mac, in_addr_t ip)
{
	if (mc_mac == NULL)
		return;

	mc_mac[0] = 0x01;
	mc_mac[1] = 0x00;
	mc_mac[2] = 0x5e;
	mc_mac[3] = (uint8_t)((ip>> 8)&0x7f);
	mc_mac[4] = (uint8_t)((ip>>16)&0xff);
	mc_mac[5] = (uint8_t)((ip>>24)&0xff);
}

void create_mac_from_ip(unsigned char* mac, in_addr_t ip)
{
	if (IN_MULTICAST(htonl(ip))) {
		create_multicast_mac_from_ip(mac, ip);
	}
	else {
		//create_unicast_mac_from_ip(mac, ip);
		fprintf(stderr, "Can't map unicast ip addr to mac\n");
	}
	printf("Translated mac: %02X:%02X:%02X:%02X:%02X:%02X\n",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

}

static void usage(const char *argv0)
{
	printf("Usage: %s --ip_addr=<ip> [--port=<port>] [--ib_dev=<dev>] [--ib-port=<port>]\n", argv0);
	printf("\n");
	printf("Options:\n");
	printf("  -i, --ip_addr=<ip>     packet's dest ip address to add filter <ip>\n");
	printf("  -p, --port=<port>      packet's dest udp port to add filter <port> (default 11111)\n");
	printf("  -d, --ib-dev=<dev>     use IB device <dev> (default first device found)\n");
	printf("  --ib-port=<port>   use port <port> of IB device (default 1)\n");
}

int main(int argc, char *argv[])
{
	struct ibv_device **ib_dev_list;
	struct ibv_device  *ib_dev;
	struct ibv_context *ib_ctx;
	struct ibv_pd *pd;
	char  *ib_devname = NULL;
	int    ib_port = 1;
	uint8_t mac[ETH_ALEN] = { 0, 0, 0, 0, 0, 0};
	struct in_addr dst_ip_addr = { INADDR_ANY };
	unsigned int dsp_udp_port = UDP_PORT_DEFAULT;
	int ret;

	/* 1. Parse user options from command line */
	while (1) {
		static struct option long_options[] = {
			{ .name = "ip-addr",  .has_arg = 1, .val = 'i' },
			{ .name = "port",     .has_arg = 1, .val = 'p' },
			{ .name = "ib-dev",   .has_arg = 1, .val = 'd' },
			{ .name = "ib-port",  .has_arg = 1, .val = 'P' },
			{ 0 }
		};

		int c = getopt_long(argc, argv, "i:p:d:P", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'i':
			inet_aton(optarg, &dst_ip_addr);
			break;

		case 'p':
			dsp_udp_port = strtoul(optarg, NULL, 0);
			if (dsp_udp_port > 65535) {
				usage(argv[0]);
				return 1;
			}
			break;

		case 'd':
			ib_devname = strdupa(optarg);
			break;

		case 'P':
			ib_port = strtol(optarg, NULL, 0);
			if (ib_port < 1) {
				usage(argv[0]);
				return 1;
			}
			break;

		default:
			usage(argv[0]);
			return 1;
		}
	}


	/* 2. Get the list of offload capable devices */
	ib_dev_list = ibv_get_device_list(NULL);
	if (!ib_dev_list) {
		fprintf(stderr, "Failed to get IB devices list (errno=%m %d)\n", errno);
		exit(1);
	}

	/* 3. Get Device */
	/* Use the first adapter (device) we find on the list (dev_list[0]).
	 * or look for what user provided as specific ibv_devname */
	if (!ib_devname) {
		ib_dev = *ib_dev_list;
		if (!ib_dev) {
			fprintf(stderr, "No IB devices found\n");
			return 1;
		}
	} else {
		int i;
		for (i = 0; ib_dev_list[i]; ++i)
			if (!strcmp(ibv_get_device_name(ib_dev_list[i]), ib_devname))
				break;
		ib_dev = ib_dev_list[i];
		if (!ib_dev) {
			fprintf(stderr, "IB device '%s' not found\n", ib_devname);
			return 1;
		}
	}
	printf("Using ib device: '%s'\n", ibv_get_device_name(ib_dev));

	/* 4. Get the device context */
	/* Get context to device. The context is a descriptor and needed for resource tracking and operations */
	ib_ctx = ibv_open_device(ib_dev);
	if (!ib_ctx) {
		fprintf(stderr, "Couldn't get ib_ctx for '%s' (errno=%m %d)\n", ibv_get_device_name(ib_dev), errno);
		exit(1);
	}

	/* 5. Allocate Protection Domain */
	/* Allocate a protection domain to group memory regions (MR) and rings */
	pd = ibv_alloc_pd(ib_ctx);
	if (!pd) {
		fprintf(stderr, "Couldn't allocate PD (errno=%m %d)\n", errno);
		exit(1);
	}

	/* 6. Create Complition Queue (CQ) */
	struct ibv_cq *cq;
	cq = ibv_create_cq(ib_ctx, RQ_NUM_DESC + SQ_NUM_DESC, NULL, NULL, 0);
	if (!cq) {
		fprintf(stderr, "Couldn't create CQ (errno=%m %d)\n", errno);
		exit (1);
	}

	/* 7. Initialize QP */
	struct ibv_qp *qp;
	struct ibv_qp_init_attr qp_init_attr = {
			.qp_context = NULL,
			/* report receive completion to cq */
			.send_cq = cq,
			.recv_cq = cq,

			.cap = {
					/* no send ring */
					.max_send_wr = SQ_NUM_DESC,
					/* maximum number of packets in ring */
					.max_recv_wr = RQ_NUM_DESC,
					/* only one pointer per descriptor */
					.max_recv_sge = 1,
			},
			.qp_type = IBV_QPT_RAW_PACKET,
	};


	/* 8. Create Queue Pair (QP) - Receive Ring */
	qp = ibv_create_qp(pd, &qp_init_attr);
	if (!qp)  {
		fprintf(stderr, "Couldn't create RAW PACKET QP (errno=%m %d)\n", errno);
		exit(1);
	}

	/* 9. Initialize the QP (receive ring) and assign a port */
	struct ibv_qp_attr qp_attr;
	int qp_flags;
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_flags = IBV_QP_STATE | IBV_QP_PORT;
	qp_attr.qp_state        = IBV_QPS_INIT;
	qp_attr.port_num        = 1;
	ret = ibv_modify_qp(qp, &qp_attr, qp_flags);
	if (ret < 0) {
		fprintf(stderr, "failed modify qp to init\n");
		exit(1);
	}
	memset(&qp_attr, 0, sizeof(qp_attr));

	/* 10. Move ring state to ready to receive, this is needed in order to be able to receive packets */
	qp_flags = IBV_QP_STATE;
	qp_attr.qp_state = IBV_QPS_RTR;
	ret = ibv_modify_qp(qp, &qp_attr, qp_flags);
	if (ret < 0) {
		fprintf(stderr, "failed modify qp to receive\n");
		exit(1);
	}

	/* 11. map IP address to MAC Address for steering rule */
	printf("Target <ip:port>: %d.%d.%d.%d:%d\n", NIPQUAD(dst_ip_addr.s_addr), dsp_udp_port);
	create_mac_from_ip(mac, dst_ip_addr.s_addr);

	/* 12. Prepare steering rule to intercept packet to DEST_MAC and place packet in ring pointed by ->qp */
	struct raw_eth_flow_attr {
		struct ibv_flow_attr         attr;
		struct ibv_flow_spec_eth     spec_eth;
		struct ibv_flow_spec_ipv4    spec_ipv4;
		struct ibv_flow_spec_tcp_udp spec_udp;
	} __attribute__((packed)) flow_attr = {
		.attr = {
			.comp_mask    = 0,
			.type         = IBV_FLOW_ATTR_NORMAL,
			.size         = sizeof(flow_attr),
			.priority     = 0,
			.num_of_specs = 3,
			.port         = PORT_NUM,
			.flags        = 0,
		},
		.spec_eth = {
			.type = IBV_FLOW_SPEC_ETH,
			.size = sizeof(struct ibv_flow_spec_eth),
			.val = {
				.dst_mac = { mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]},
				.src_mac = { 0, 0, 0, 0, 0, 0},
				.ether_type = ntohs(ETH_P_IP),
				.vlan_tag = 0,
			},
			.mask = {
				.dst_mac = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
				.src_mac = { 0, 0, 0, 0, 0, 0},
				.ether_type = 0xFFFF,
				.vlan_tag = 0,
			}
		},
		.spec_ipv4 = {
			.type = IBV_FLOW_SPEC_IPV4,
			.size = sizeof(struct ibv_flow_spec_ipv4),
			.val = {
				.dst_ip = dst_ip_addr.s_addr,
				.src_ip = 0x00000000,
			},
			.mask = {
				.dst_ip = 0xFFFFFFFF,
				.src_ip = 0x00000000,
			}
		},
		.spec_udp = {
			.type = IBV_FLOW_SPEC_UDP,
			.size = sizeof(struct ibv_flow_spec_tcp_udp),
			.val = {
				.dst_port = htons(dsp_udp_port),
				.src_port = 0x0000,
			},
			.mask = {
				.dst_port = 0xFFFF,
				.src_port = 0x0000,
			}
		}
	};

	/* 13. Add the steering rule in HW */
	struct ibv_flow *flow_id;
	flow_id = ibv_create_flow(qp, &flow_attr.attr);
	if (!flow_id) {
		printf("failude\n");
		fprintf(stderr, "Couldn't attach steering flow (errno=%m %d)\n", errno);
		exit(1);
	}
	printf("Filter flow created\n");

	/* 14. Wait for user to exit: Ctrl-C */
	printf("Hit Ctril-C to exit\n");
	while (1) {
		sleep(1000);
	}

	// 15. All done, system will clear the resources
	// printf("We are done\n");
	return 0;
}
