/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 *
 * Based on TI McSDK NETAPI library
 */

/* Standard includes */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <odp_ti_mcsdk.h>
#include <odp_debug_internal.h>

/* Socket Includes */
#include "sockutils.h"
#include "sockrmmsg.h"

/* RM Includes */
#include <ti/drv/rm/rm.h>
#include <ti/drv/rm/rm_transport.h>
#include <ti/drv/rm/rm_services.h>

/* Test FALSE */
#define RM_TEST_FALSE			0
/* Test TRUE */
#define RM_TEST_TRUE			1

/* Socket timeout */
#define CLIENT_SOCK_TIMEOUT_USEC	500

/* Application's registered RM transport indices */
#define SERVER_TO_CLIENT		0
/* Maximum number of registered RM transports */
#define MAX_MAPPING_ENTRIES		1

/* RM registered transport mapping structure */
struct trans_map_entry_s {
	/* Registered RM transport handle */
	Rm_TransportHandle transportHandle;
	/* Remote socket tied to the transport handle */
	sock_name_t *remote_sock;
};

/* Client instance name */
char rm_client_name[RM_NAME_MAX_CHARS] = "RM_Client0";

/* Client socket name */
char rm_client_sock_name[] = "/tmp/var/run/rm/rm_client";

/* Client socket handle */
sock_h rm_client_socket;

/* Client instance handles */
Rm_Handle rm_client_handle;

/* Transport map stores the RM transport handle to IPC MessageQ mapping */
struct trans_map_entry_s rm_transport_map[MAX_MAPPING_ENTRIES];

hplib_spinLock_T net_rm_lock;


static Rm_Packet *transport_alloc(Rm_AppTransportHandle transport ODP_UNUSED,
					uint32_t pkt_size,
					Rm_PacketHandle *pkt_handle)
{
	Rm_Packet *rm_pkt = NULL;

	rm_pkt = calloc(1, sizeof(*rm_pkt));
	if (!rm_pkt) {
		odp_pr_err("can't malloc for RM send message (err: %s)\n",
			   strerror(errno));
		return NULL;
	}
	rm_pkt->pktLenBytes = pkt_size;
	*pkt_handle = rm_pkt;

	return rm_pkt;
}

static void transport_free(Rm_Packet *rm_pkt)
{
	if (rm_pkt)
		free(rm_pkt);
}

static void transport_receive(void)
{
	int32_t rm_result;
	int retval;
	int length = 0;
	sock_name_t server_sock_addr;
	Rm_Packet *rm_pkt = NULL;
	struct sockaddr_un server_addr;

	retval = sock_wait(rm_client_socket, &length, NULL, -1);
	if (retval == -2) {
		/* Timeout */
		return;
	} else if (retval < 0) {
		odp_pr_err("Error in reading from socket, error %d\n", retval);
		return;
	}

	if (length < (int)sizeof(*rm_pkt)) {
		odp_pr_err("invalid RM message length %d\n", length);
		return;
	}
	rm_pkt = calloc(1, length);
	if (!rm_pkt) {
		odp_pr_err("can't malloc for recv'd RM message (err: %s)\n",
			   strerror(errno));
		return;
	}

	server_sock_addr.type = sock_addr_e;
	server_sock_addr.s.addr = &server_addr;
	retval = sock_recv(rm_client_socket, (char *)rm_pkt, length,
			   &server_sock_addr);
	if (retval != length) {
		odp_pr_err("recv RM pkt failed from socket, received = %d, expected = %d\n",
			   retval, length);
		return;
	}

	odp_pr_vdbg("received RM pkt of size %d bytes from %s\n", length,
		    server_sock_addr.s.addr->sun_path);

	/* Provide packet to RM Server for processing */
	rm_result = Rm_receivePacket(
			rm_transport_map[SERVER_TO_CLIENT].transportHandle,
			rm_pkt);
	if (rm_result != RM_OK)
		odp_pr_err("RM failed to process received packet: %d\n",
			   rm_result);

	transport_free(rm_pkt);
}

static int32_t transport_send_rcv(Rm_AppTransportHandle app_transport,
			Rm_PacketHandle pkt_handle)
{
	sock_name_t *server_sock_name = (sock_name_t *)app_transport;
	Rm_Packet *rm_pkt = (Rm_Packet *)pkt_handle;

	hplib_mSpinLockLock(&net_rm_lock);
	if (sock_send(rm_client_socket, (char *)rm_pkt,
		      (int)rm_pkt->pktLenBytes, server_sock_name)) {
		odp_pr_err("send data failed\n");
		hplib_mSpinLockUnlock(&net_rm_lock);
		return -1;
	}

	/* Wait for response from Server */
	transport_receive();
	hplib_mSpinLockUnlock(&net_rm_lock);

	return 0;
}

static int connection_setup(void)
{
	Rm_TransportCfg transport_cfg;
	int i;
	sock_name_t sock_name;
	int32_t result = 0;
	char server_sock_name[] = RM_SERVER_SOCKET_NAME;

	/* Initialize the transport map */
	for (i = 0; i < MAX_MAPPING_ENTRIES; i++)
		rm_transport_map[i].transportHandle = NULL;

	sock_name.type = sock_name_e;
	sock_name.s.name = rm_client_sock_name;

	rm_client_socket = sock_open(&sock_name);
	if (!rm_client_socket) {
		odp_pr_err("Client socket open failed\n");
		return -1;
	}

	rm_transport_map[SERVER_TO_CLIENT].remote_sock =
			calloc(1, sizeof(sock_name_t));
	rm_transport_map[SERVER_TO_CLIENT].remote_sock->type =
			sock_name_e;
	rm_transport_map[SERVER_TO_CLIENT].remote_sock->s.name =
			calloc(1, strlen(server_sock_name) + 1);
	strncpy(rm_transport_map[SERVER_TO_CLIENT].remote_sock->s.name,
		server_sock_name, strlen(server_sock_name) + 1);

	/* Register the Server with the Client instance */
	transport_cfg.rmHandle = rm_client_handle;
	transport_cfg.appTransportHandle = (Rm_AppTransportHandle)
			rm_transport_map[SERVER_TO_CLIENT].remote_sock;
	transport_cfg.remoteInstType = Rm_instType_SERVER;
	transport_cfg.transportCallouts.rmAllocPkt = transport_alloc;
	transport_cfg.transportCallouts.rmSendPkt = transport_send_rcv;
	rm_transport_map[SERVER_TO_CLIENT].transportHandle =
			Rm_transportRegister(&transport_cfg, &result);

	return 0;
}

static int free_all_resources(Rm_ServiceHandle *rm_service)
{
	Rm_ServiceReqInfo request;
	Rm_ServiceRespInfo response;
	return 0;
	memset((void *)&request, 0, sizeof(request));
	memset((void *)&response, 0, sizeof(response));

	request.type = Rm_service_RESOURCE_FREE;
	request.resourceName = "ALL";
	request.resourceBase = RM_RESOURCE_BASE_UNSPECIFIED;
	request.resourceLength = 0;
	request.resourceAlignment = 0;
	/* RM will block until resource is returned since callback is NULL */
	request.callback.serviceCallback = NULL;
	odp_pr_dbg("resourceName: %s\n", request.resourceName);
	rm_service->Rm_serviceHandler(rm_service->rmHandle, &request,
				     &response);
	odp_pr_dbg("serviceState: %d\n", response.serviceState);

	return (response.serviceState == RM_SERVICE_APPROVED) ? 0 : 1;
}

Rm_ServiceHandle *rm_client_init(void)
{
	Rm_InitCfg init_cfg;
	int32_t result;
	Rm_ServiceHandle *service_handle = NULL;

	hplib_mSpinLockInit(&net_rm_lock);

	odp_pr_dbg("RM Version : 0x%08x\nVersion String: %s\n", Rm_getVersion(),
		   Rm_getVersionStr());

	/* Initialize the RM Client */
	memset(&init_cfg, 0, sizeof(init_cfg));
	init_cfg.instName = rm_client_name;
	init_cfg.instType = Rm_instType_CLIENT;
	init_cfg.instCfg.clientCfg.staticPolicy = NULL;

	rm_client_handle = Rm_init(&init_cfg, &result);
	if (result != RM_OK) {
		odp_pr_err("%s: Initialization failed\n", rm_client_name);
		return NULL;
	}

	odp_pr_dbg("Initialized %s\n", rm_client_name);

	/* Open Client service handle */
	service_handle = Rm_serviceOpenHandle(rm_client_handle, &result);
	if (result != RM_OK) {
		odp_pr_err("%s: Service handle open failed\n", rm_client_name);
		return NULL;
	}

	if (connection_setup())
		return NULL;

	free_all_resources(service_handle);

	return service_handle;
}
