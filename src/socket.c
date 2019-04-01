#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/epoll.h>

#include "misc.h"

extern int debug;
extern int ci_number;
extern int camd_open;
extern int camd_client; /* make a client connection instead of server */
extern int assigned;
extern int descrambles;
extern char fullserviceref[64];
extern char ci_name[128];

struct socket_cb {
	struct ci_session *ci;
	void (*cb)(struct ci_session *s, uint8_t *data, int len);
};

char devname[64];
static char *socket_open_template_client = "/tmp/.listen.camd.socket";
static char *socket_open_template = "/tmp/camd.socket";
static char *socket_template = "/var/run/ca/ci%d.socket";

#define MAX_CB  2

struct socket_cb cbs[MAX_CB];

int socket_install_cb(struct ci_session *ci, void *cb)
{
	int i;

	/* check if we know this session already */
	for (i = 0; i < MAX_CB; i++) {
		if (cbs[i].ci == ci) {
			cbs[i].cb = cb;
			return 0;
		}
	}

	/* check if we got space for a cb */
	for (i = 0; i < MAX_CB; i++) {
		if (!cbs[i].ci) {
			cbs[i].ci = ci;
			cbs[i].cb = cb;
			return 0;
		}
	}

	return -1;
}

int socket_uninstall_cb(struct ci_session *ci, void *cb)
{
	int i;

	for (i = 0; i < MAX_CB; i++) {
		if (cbs[i].ci == ci) {
			cbs[i].ci = NULL;
			cbs[i].cb = NULL;
			return 0;
		}
	}

	return -1;
}

int fcntl_nb(int fd)
{
	int fl;

	fl = fcntl(fd, F_GETFL);
	if (fl == -1)
		return -1;

	fl |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, fl) == -1)
		return -1;

	return 0;
}

int socket_server_event(int socket_fd, uint32_t events)
{
	struct sockaddr *address=0;
	socklen_t *address_length=0;
	int connection_fd;

	connection_fd = accept(socket_fd, address, address_length);
	if (connection_fd < 0) {
        	if (debug > 0) lprintf("accept error: %s\n",strerror(errno));   
		return -1;
	}

	fcntl_nb(connection_fd);
	return connection_fd;
}

int socket_client_event(int connection_fd, uint32_t events)
{
	if ((events & (EPOLLIN | EPOLLHUP)) == (EPOLLIN | EPOLLHUP)) 
                {
	        if (camd_client)
		   {
	 	   if (debug > 0) lprintf("Open Client hangup\n");
		   return -2;
		   }
		if (debug > 0) lprintf("Client hangup\n");
	        return -1;
	        }

	if (events & EPOLLIN) {
		unsigned char buf[1024];
		ssize_t len;

		if (debug > 2) lprintf("Client data\n");

		len = recv(connection_fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (len < 0) {
	        	if (debug > 0) lprintf("recv error: %s\n",strerror(errno));   
			return -1;
		}
		if (debug > 4) hexdump(buf, len);
		if (buf[2] == 0x32) {
   	                if (!check_ci_assignment(buf, len))
				{                            
				assigned=1;
                		}            
			else
				{                            
				assigned=0;
				return -1;
                		}            
			}
			
		if (len == 0)
			return -1;

		if (buf[2] == 0x32) {
			int llen, plen, i;
			llen = parseLengthField(buf + 3, &plen);
			for (i = 0; i < MAX_CB; i++)
				if (cbs[i].cb)
					cbs[i].cb(cbs[i].ci, buf + 3 + llen, plen);
		}
		return 0;
	}

//	if (debug > 0) lprintf("Unhandled event: %x\n", events);
	return 0;
}

int socket_init(unsigned int slot_index)
{
	struct sockaddr_un address;
	int socket_fd;

	mkdir("/var/run/ca", 0777);

	if (!camd_open)
	   {	
	   /* server will be accepted */
   	   snprintf(devname, sizeof(devname), socket_template, slot_index);
	   }
        else
	   {	
	   if (camd_client)
		{
                strncpy(devname, socket_open_template_client, sizeof(devname));
		}
	   else
		{
                strncpy(devname, socket_open_template, sizeof(devname));
		}
	   }

        if (debug > 9) lprintf("CI%d CONNECT %s\n", ci_number, devname);

	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (socket_fd < 0) 
                {
        	if (debug > 0) lprintf("socket error: %s\n",strerror(errno));   
//		return -1;
	        }

	memset(&address, 0, sizeof(struct sockaddr_un));
	address.sun_family = AF_UNIX;
	strcpy(address.sun_path, devname);

	if (!camd_client)
	   {
	   unlink(devname);

	   if (bind(socket_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_un)) != 0) 
                {
        	if (debug > 0) lprintf("bind error: %s\n",strerror(errno));   
		return -1;
	        }

	   if (listen(socket_fd, 5) != 0) 
                {
        	if (debug > 0) lprintf("listen error: %s\n",strerror(errno));   
		return -1;
		}
	   }
        else
	   {
	   /* just connect to server as we are client */
	   if(connect(socket_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_un)) < 0)
		{
        	if (debug > 0) lprintf("connect error: %s\n",strerror(errno));   
		return -1;
		}
	   }

	fcntl_nb(socket_fd);
	return socket_fd;
}

void socket_exit(int socket_fd, unsigned int slot_index)
{
	close(socket_fd);
	if (!camd_client)
	   {
	   if (strlen(devname) > 0)
  	   	unlink(devname);
	   }
}
