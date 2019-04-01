int v1=9;
int v2=7;
#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <signal.h>
#include <linux/dvb/ca.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <getopt.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/mount.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>

#include "session.h"
#include "resource.h"
#include "misc.h"
#include "descrambler.h"
#include "list.h"
#include "socket.h"

/* define some colors */
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

#define MAX_PID_REMOVE 8192

/* some stuff is better global */
int  descrambles=0;
int  assigned=0;
int  current=0;
int  classic=0;
char ci_name[128];
char ci_name_underscore[128];
int  ci_number;
int  debug=0;
int  logging=0;
int  resetting=0;
int  foreground=0;
int  autopin=0;
enum { NONE, START, STOP, RESTART } ci_command=NONE;
int  extract_ci_cert=0;
char oldpids[256];
char cachedpids[256];
int  ca_device=0;
char demux_device[24]; 
int  connect_mmi=1;
int  uri_version=1;
int  bcd_time=1;
int  camd_open=0;
int  camd_client=1;
int  idle=1;
char logfile[256];
char old_buf_tuner[8];
char old_buf_device[32];
char old_buf_module[32];
char fullserviceref[64];
char currentref[64];
struct utsname u;
char *dreambox;  

int  quiet=1; /* qiet is default on */
char authie[7];
char devie[7];

/* FIFO */
int fifo_pipe=1;
int fifo;
int fifo_named=0;
int fifo_handler=0;
int fifo_request=0;
int fifo_call=0;
time_t fifo_time=0;     
time_t current_time=0;     
time_t last_access=0;
time_t current_access=0;

char cdev[10];
char cdev2[10];
char pdev[16];
char pdev2[16];

#define SIGRESTART      99
#define RCV_SIZE        4096
#define MAX_SESSIONS    256
#define MAX_RESOURCES   64
#define MAX_TIMEOUT     1200

pid_t enigma2_pid=0;	
extern pid_t GetPIDbyName_Wrapper(const char* cchrptr_ProcessName, ... );

int standalone=0;
char *dream_ci_bin="/usr/bin/dreamciplus";
char *dream_ci_bin_mipsel="/usr/bin/dreamciplus-mipsel";
char *dream_ci_bin_armhf="/usr/bin/dreamciplus-armhf";

char *dream_ci_so="/usr/bin/_dreamciplus.so";
char *dream_ci_so_mipsel="/usr/bin/_dreamciplus-mipsel.so";
char *dream_ci_so_armhf="/usr/bin/_dreamciplus-armhf.so";

char *dream_ci_legacy1="/lib/systemd/system/dreamciplus0.service";
char *dream_ci_legacy2="/lib/systemd/system/dreamciplus1.service";
char *dream_ci_legacy3="/etc/systemd/system/multi-user.target.wants/dreamciplus0.service";
char *dream_ci_legacy4="/etc/systemd/system/multi-user.target.wants/dreamciplus1.service";
char *dream_ci_legacy5="/usr/bin/enigma2_pre_start_ciplus.sh";

#define GetPIDbyName(ProcessName,...) GetPIDbyName_Wrapper(ProcessName, ##__VA_ARGS__, (int) 15)

int start(int slot);
int stop(int slot);
int restart(int slot);
int dreamciplus(int command, int slot);

int max_ci=2;

int timerfd;
static struct ci_module ci;

struct ci_buffer {
	struct list_head list;
	size_t size;
	unsigned char data[];
};

struct ci_module {
	/* slot state */
	int slot_state;

	/* which slot */
	int slot_index;

	/* fop */
	int fd;

	/* tx */
	struct list_head *txq;
	struct list_head *mmiq;

	/* session */
	struct ci_session session[MAX_SESSIONS];

	/* resources */
	const struct ci_resource *resources[MAX_RESOURCES];

	char app_name[64];

	int epoll;
	int camd_socket;
	int mmi_socket;
	bool mmi_connected;

	int res_camgr_ready;    /* ca_mgr got caids */
	int res_ccmgr_ready;    /* content_control is ready */
	int res_ccmgr_timeout;  /* time we wait for content_control session */
};

static void mmi_set_appname(struct ci_module *ci);

// maximal 10 MB logfile at /tmp
#define MAXLOG 10240

void lprintf(char* message,...)
{
    char newMessage[16384];
    FILE *logout;
    struct stat st;
    int logsize;

    va_list args;
    va_start(args, message);
    vsprintf(newMessage, message, args);

    char buff[100];
    time_t now = time (0);
    strftime (buff, 100, "DCP %Y-%m-%d %H:%M:%S", localtime (&now));
    if (logging)
       {
       if (stat(logfile, &st) == 0)
	  {
       	  logsize = (int) st.st_size/1024;
	  if (logsize > MAXLOG)
             {
             remove(logfile);
	     }
	  }
       logout = fopen(logfile, "a");
       if (logout > 0)
	   {
           if (strlen(newMessage) > 1) fprintf(logout,"[%s] ", buff);
           fprintf(logout,"%s",newMessage);
	   fclose(logout);
           }
       }
    else
       {
       if (strlen(newMessage) > 1) fprintf(stdout,"[%s] ", buff);
       fprintf(stdout,"%s",newMessage);
       fflush(stdout);
       }
}

void cert_strings(char *certfile)
{
	int c;
	unsigned count;
//	off_t offset;
	FILE *file;
	FILE *output;
	char string[256];
	int n=2; /* too short string to be usefull */ 
	int line=0;
        if (logging)
           {
       	   output = fopen(logfile, "a");
       	   if (output <= 0) return;
	   }
	else
           {
	   output=stdout;
	   }

	file = fopen(certfile,"r");
	if (!file) 
		{
		return;
		}
	fprintf(output,"#########################################################\n");
//	offset = 0;
	count = 0;
	do 
		{
		if (line > 14) n=8; /* after usefull info be stricter */
		c = fgetc(file);
//		if (isprint(c) || c == '\t') 
		if (isprint(c)) 
			{
			string[count] = c;
			count++;
			}
		else 
			{
			if (count > n) /* line feed */
				{
				string[count-1]=0;
				fprintf(output, "%s\n", string);
				line++;
				}
			count = 0;
			}
//		offset++;
		} 
	while ((c != EOF) && (line < 16)); /* only frst 15 lines */
	fclose(file);
	fprintf(output,"#########################################################\n");
        if (logging)
           {
       	   fclose(output);
	   }
	return;
}

void hexdump(const uint8_t *data, unsigned int len)
{
FILE *logout;
if (debug > 0)
	{
        char buff[100];
        time_t now = time (0);
        strftime (buff, 100, "DCP %Y-%m-%d %H:%M:%S", localtime (&now));
        if (logging)
           {
           logout = fopen(logfile, "a");
           if (logout > 0)
		 {
       	   	 fprintf(logout,KYEL "[%s] ----------------------------------------------\n", buff);
	   	 while (len--)
		     fprintf(logout, "%02x ", *data++);
	         fprintf(logout, KNRM "\n");
		 fclose(logout);
		 }
	   }
	else
           {
       	   fprintf(stdout,KYEL "[%s] -----------------------------------------------------\n", buff);
	   while (len--)
		fprintf(stdout, "%02x ", *data++);
	   fprintf(stdout, KNRM "\n");
	   }
	}
}
	

static struct ci_buffer *ci_buffer_new(const void *data, size_t size)
{
	struct ci_buffer *buf;

	buf = malloc(sizeof(struct ci_buffer) + size);
	if (buf == NULL) {
		if (debug > 0) lprintf("malloc failed\n");
		return NULL;
	}

	list_init(buf);
	buf->size = size;
	memcpy(buf->data, data, size);
	return buf;
}

static int ci_resmgr_receive(struct ci_session *session, const uint8_t *tag, const uint8_t *data, unsigned int len)
{
	if ((tag[0] == 0x9f) && (tag[1] == 0x80)) {
		switch (tag[2]) {
		case 0x10:
			if (debug > 3) lprintf("profile enquiry\n");
			session->state = ProfileEnquiry;
			return 1;
		case 0x11:
			if (debug > 3) lprintf("resmgr is final\n");
			if (session->state == FirstProfileEnquiry)
				{
				if (debug > 3) lprintf("but first enquiry\n");
				return 1; /* further action is needed */
				}
			session->state = Final;
			break;
		default:
			if (debug > 0) lprintf("unknown apdu tag %02x\n", tag[2]);
			break;
		}
	}
	return 0;
}

static void ci_resmgr_doAction(struct ci_session *session)
{
	struct ci_module *ci = session->ci;

	switch (session->state) {
	case started:
	{
		if (debug > 9) lprintf("resmgr_doAction started ...\n");
		uint8_t tag[3] = { 0x9f, 0x80, 0x10 };
		ci_session_sendAPDU(session, tag, 0, 0);
		session->state = FirstProfileEnquiry;
		ci->res_ccmgr_timeout = 0;
		break;
	}
	case FirstProfileEnquiry:
	{
		if (debug > 9) lprintf("resgmr_doAction first enquiry ...\n");
		uint8_t tag[3] = { 0x9f, 0x80, 0x12 };
		ci_session_sendAPDU(session, tag, 0, 0);
		session->state = ProfileChange;
		session->action = 0;
		break;
	}
	case ProfileEnquiry:
	{
		if (debug > 9) lprintf("resmgr_doAction profile enquiry ...\n");
		uint8_t tag[3] = { 0x9f, 0x80, 0x11 };
		uint8_t data[MAX_RESOURCES * 4];
		int pos = 0;
		int i;

		for (i = 0; i < MAX_RESOURCES; i++) {
			if (ci->resources[i]) {
				BYTE32(data + pos, ci->resources[i]->id);
				pos += 4;
			}
		}
		if (debug > 4) hexdump(data, pos);

		ci_session_sendAPDU(session, tag, data, pos);
		session->state = Final;
		session->action = 0;
		break;
	}
	default:
		if (debug > 9) lprintf("resmgr_doAction unknown ...\n");
	}
}

static int buildLengthField(uint8_t *pkt, int len)
{
	if (len < 127) {
		*pkt++ = len;
		return 1;
	} else if (len < 256) {
		*pkt++ = 0x81;
		*pkt++ = len;
		return 2;
	} else if (len < 65536) {
		*pkt++ = 0x82;
		*pkt++ = len >> 8;
		*pkt++ = len;
		return 3;
	} else {
		if (debug > 0) lprintf("too big for lengthField\n");
		return 0;
	}
}

static struct ci_session *ci_session_create(struct ci_module *ci, uint32_t res_id, uint8_t *status)
{
	struct ci_session *session;
	unsigned int i;

	if (debug > 3) lprintf("req for session with id %x\n", res_id);

	for (i = 0; i < MAX_SESSIONS; i++) 
		{
		session = &ci->session[i];
		if (session->state == unused)
			break;
		}

	if (i == MAX_SESSIONS) 
		{
		if (status)
			*status = 0xf3;
		if (debug > 3) lprintf("MAX SESSIONS\n");
		return NULL;
		}

	if (debug > 3) lprintf("inCreation\n");
	session->state = inCreation;
	session->resid = res_id;

	for (i = 0; i < MAX_RESOURCES; i++) 
		{
		if (ci->resources[i] && (ci->resources[i]->id == res_id)) 
			{
			session->resource = ci->resources[i];
			break;
			}
		}

	if (status)
		*status = 0;

	return session;
}

static struct ci_session *ci_session_by_index(struct ci_module *ci, uint16_t index)
{
	struct ci_session *session;
	int i;

	for (i = 0; i < MAX_SESSIONS; i++) 
		{
		session = &ci->session[i];
		if ((session->state != unused) && (session->index == index))
			return session;
		}
	if (debug > 0) lprintf("no index session found\n");

	return NULL;
}

static struct ci_session *ci_session_by_resource_id(struct ci_module *ci, uint32_t id)
{
	struct ci_session *session;
	int i;

	for (i = 0; i < MAX_SESSIONS; i++) 
		{
		session = &ci->session[i];
		if (session->state != unused && session->resource && session->resource->id == id)
			return session;
		}
	if (debug > 0) lprintf("no resource session found\n");

	return NULL;
}

static void ci_list_enqueue(struct list_head **list, const uint8_t *data, size_t len)
{
	struct ci_buffer *buf;

	if (debug > 10) hexdump(data, len);
	buf = ci_buffer_new(data, len);
	if (buf != NULL)
		list_add_tail(list, buf);
}

static void ci_list_dequeue(struct list_head **list, int fd)
{
	struct ci_buffer *buf;

	if (!list || list_empty(*list)) 
		{
		assert(0);
		return;
		}

	buf = list_pop_front(list, struct ci_buffer);
	if (debug > 10) hexdump(buf->data, buf->size);
	if (write(fd, buf->data, buf->size) != (ssize_t)buf->size)
		{
		if (debug > 0) lprintf("write failed %d\n", buf->size);
		}

	free(buf);
}

static void ci_mmi_enqueue(struct ci_module *ci, const uint8_t *data, size_t len)
{
	if (debug > 10) lprintf(">>>>>> MMI ENQUEUE\n");
	ci_list_enqueue(&ci->mmiq, data, len);
}

static void ci_mmi_dequeue(struct ci_module *ci)
{
	if (debug > 10) lprintf(">>>>>> MMI WRITE\n");
	ci_list_dequeue(&ci->mmiq, ci->mmi_socket);
}

static void ci_session_enqueue(struct ci_module *ci, const uint8_t *data, size_t len)
{
	if (debug > 10) lprintf(">>>>>> CI ENQUEUE\n");
	ci_list_enqueue(&ci->txq, data, len);
}

static void ci_session_dequeue(struct ci_module *ci)
{
	if (debug > 10) lprintf(">>>>>> CI WRITE\n");
	ci_list_dequeue(&ci->txq, ci->fd);
}

static void ci_session_sendSPDU(struct ci_module *ci, uint8_t tag, const uint8_t *data, size_t len, uint16_t session_nb)
{
	uint8_t pkt[RCV_SIZE];
	uint8_t *ptr = pkt;

	*ptr++ = tag;
	ptr += buildLengthField(ptr, len + 2);
	if (data)
		memcpy(ptr, data, len);
	ptr += len;
	*ptr++ = session_nb >> 8;
	*ptr++ = session_nb;

	if (debug > 4) hexdump(pkt, ptr - pkt);

	ci_session_enqueue(ci, pkt, ptr - pkt);
}

static void ci_session_sendSPDU_A(struct ci_module *ci, uint8_t tag, const uint8_t *data, size_t len, uint16_t session_nb)
{
	uint8_t pkt[RCV_SIZE];
	uint8_t *ptr = pkt;
        size_t nlen;
	if (classic)
		nlen = len; 
	else
		nlen = 0;   /* more fun */

	*ptr++ = tag;
	ptr += buildLengthField(ptr, nlen + 2);
	if (!classic)
		ptr += nlen;

	*ptr++ = session_nb >> 8;
	*ptr++ = session_nb;

	if (data)
		memcpy(ptr, data, len);
	ptr += len;

	if (debug > 4) hexdump(pkt, ptr - pkt);

	ci_session_enqueue(ci, pkt, ptr - pkt);
}

void ci_session_sendAPDU(struct ci_session *session, const uint8_t *tag, const uint8_t *data, size_t len)
{
	uint8_t pkt[len + 3 + 4];
	int l;

	memcpy(pkt, tag, 3);
	l = buildLengthField(pkt + 3, len);
	if (data)
		memcpy(pkt + 3 + l, data, len);
	ci_session_sendSPDU_A(session->ci, 0x90, pkt, len + 3 + l, session->index);
}

void ci_session_set_app_name(struct ci_session *session, const uint8_t *data, size_t len)
{
	struct ci_module *ci = session->ci;

	if (len >= sizeof(ci->app_name))
		len = sizeof(ci->app_name) - 1;

	memcpy(ci->app_name, data, len);
	ci->app_name[len] = '\0';
	init_strip_table();
	strip(ci->app_name, IS_CTRL | IS_EXT);

	if (debug > 0) lprintf("MODULE NAME:  %s\n", ci->app_name);

	if (strlen(ci_name_underscore) > 0)
		{
        	/* remove the old CI name file */
		remove_name_file(ci_name_underscore);
		}

	/* store ci name in global variables */
	strcpy(ci_name,ci->app_name);
	strcpy(ci_name_underscore, ci_name);
        /* quickly replace blanks */
        int i=0;
        while (ci_name_underscore[i] != 0)
           {
           if (ci_name_underscore[i] == 32)
               ci_name_underscore[i]= 95; /* underscore _ */
           i++;
           };

	write_name_file(ci_name_underscore);
	last_access=0;
	current_access=0;
	if (fifo_pipe)
		{
                if (debug > 9) lprintf("CI%d FIFO NAME RESET\n",ci_number);
		/* reset time so that module name gets re-written to fifo */
		fifo_time=time(NULL); 
		fifo_named=0;
		fifo_handler=0;
		}

	if (ci->mmi_connected)
		mmi_set_appname(session->ci);
}

static void ci_session_openresponse(struct ci_module *ci, struct ci_session *session, uint8_t status)
{
	uint8_t pkt[6];

	pkt[0] = status;
	BYTE32(&pkt[1], session->resid);

	if (debug > 4) hexdump(pkt, 5);
	if (debug > 3) lprintf("open response index %d\n", session->index);
	ci_session_sendSPDU(ci, 0x92, pkt, 5, session->index);
}

static void ci_session_closeresponse(struct ci_module *ci, struct ci_session *session, uint8_t status)
{
	ci_session_sendSPDU(ci, 0x96, &status, 1, session->index);
}

static bool start_camd_socket(struct ci_module *ci)
{
	if (ci->camd_socket > 0)
		return true;

	ci->camd_socket = socket_init(ci->slot_index);
	if (ci->camd_socket < 0)
		return false;
	if (fifo_pipe)
		{
                if (debug > 9) lprintf("CI%d FIFO CAMD RESET\n",ci_number);
		fifo_time=time(NULL); 
		fifo_named=0;
		fifo_handler=0;
		}

	struct epoll_event ev;
	memset(&ev, 0, sizeof(struct epoll_event));

	ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
	ev.data.fd = ci->camd_socket;
	if (epoll_ctl(ci->epoll, EPOLL_CTL_ADD, ci->camd_socket, &ev) < 0) {
		if (debug > 0) lprintf("EPOLL_CTL_ADD error\n");
		return false;
	}

	return true;
}

static bool ci_session_receive_payload(struct ci_module *ci, struct ci_session *session, const uint8_t *pkt, size_t recv_len)
{
	int alen, hlen;

	while (recv_len > 0) {
		const uint8_t *tag = pkt;
		pkt += 3; // tag
		recv_len -= 3;
		hlen = parseLengthField(pkt, &alen);
		pkt += hlen;
		recv_len -= hlen;
		if (((recv_len-alen) > 0) && ((recv_len - alen) < 3))
			{
			if (debug > 9) lprintf("WORKAROUND: applying work around MagicAPDULength\n");
			alen=recv_len;
			}

		if (tag[0] == 0x9f && tag[1] == 0x88 && tag[2] == 0x00) {
			/* close request from module - this is a host->cam command (seen on hd+ module) */
			ci_session_sendSPDU_A(ci, 0x90, tag, 3, session->index);
			return true;
			}

		if (ci->mmi_connected && tag[0] == 0x9f && tag[1] == 0x88) 
			{
			ci_mmi_enqueue(ci, tag, 3 + hlen + alen);
			} 

		if (session->resource) 
			{
			if (debug > 3) lprintf("resource receive\n");
			if (session->resource->receive(session, tag, pkt, alen))
				session->action = 1;
			}
		else
			{
      			if (debug > 4) lprintf(">>>> %02x %02x %02x\n", tag[0], tag[1], tag[2]);
			if (debug > 4) hexdump(pkt, alen);
			}

		pkt += alen;
		recv_len -= alen;

		/* content_control is ready */
		if (tag[0] == 0x9f && tag[1] == 0x90 && tag[2] == 0x09)  /* cc_sac_sync_req */
			ci->res_ccmgr_ready = 1;

		/* ca_manager is ready */
		if (tag[0] == 0x9f && tag[1] == 0x80 && tag[2] == 0x31)  /* ca_info */
			ci->res_camgr_ready = 1;
//		if (debug > 9) lprintf("CCMGR %d CAMGR %d\n",ci->res_ccmgr_ready, ci->res_camgr_ready);

		if (ci->camd_socket < 0 && ci->res_ccmgr_ready && ci->res_camgr_ready)
			{
			if (start_camd_socket(ci) == false)
				return false;
			}
	}
	return true;
}

static bool ci_session_receivedata(struct ci_module *ci, const uint8_t *recv_buf, size_t recv_len)
{
	const uint8_t *pkt = recv_buf;
	uint8_t tag = *pkt++;
	int llen, hlen;
	struct ci_session *session;

	llen = parseLengthField(pkt, &hlen);
	pkt += llen;

	if (tag == 0x91) {               /* open_session_request */
		uint8_t status;
		session = ci_session_create(ci, UINT32(pkt, 4), &status);
		if (!session) {
			if (debug > 0) lprintf("no free session available\n");
			return false;
		}
		if (debug > 5) lprintf("got free session %d\n", session->index);
		ci_session_openresponse(ci, session, status);
//		if (debug > 3) lprintf("state %d\n", session->state);
		session->state = started;
		/* to be verified - this depends on resource or ? */
		session->action = 1;
		session->private_data = NULL;
	} else {
		uint32_t session_nb;
		if (debug > 5) lprintf("established state\n");
		session_nb = pkt[hlen - 2] << 8;
		session_nb |= pkt[hlen - 1];
		// 256 -> 1
		if (session_nb==MAX_SESSIONS)
			session_nb=1;
		if ((!session_nb) || (session_nb >= MAX_SESSIONS)) {
			if (debug > 0) lprintf("illegal session number %d\n", session_nb);
			return false;
		}

		session = ci_session_by_index(ci, session_nb);
		if (!session) {
			if (debug > 0) lprintf("session %d not found\n", session_nb);
			return false;
		}

		switch (tag) {
		case 0x90:
			if (debug > 5) lprintf("normal state\n");
			break;
		case 0x94:
			if (debug > 0) lprintf("recvCreateSessionResponse\n");
			break;
		case 0x95:
			if (debug > 0) lprintf("recvCloseSessionRequest %x\n", session->resid);
			unsigned char close_mmi[4] = { 0x9f, 0x88, 0x00, 0x00 };
			if (session->resid == 0x400041) /* if mmi - inform the socket */
				ci_mmi_enqueue(ci, close_mmi, 4);
			if (session->resource && session->resource->doClose)
				session->resource->doClose(session);
			ci_session_closeresponse(ci, session, 0);
			session->state = unused;
			break;
		default:
			if (debug > 0) lprintf("unhandled tag %02x\n", tag);
			return false;
		}
	}

	hlen += llen + 1; // lengthfield and tag

	return ci_session_receive_payload(ci, session, &recv_buf[hlen], recv_len - hlen);
}

static void ci_session_pollAll(struct ci_module *ci)
	{
	struct ci_session *session;
	int i;

	for (i = 0; i < MAX_SESSIONS; i++) {
		session = &ci->session[i];

		if (session->state == inDeletion) 
			{
			if (debug > 0) lprintf("handle session delete\n");
			} 
		else 
			{
			if ((session->state != unused) && (session->action)) 
				{
				if (session->resource)
					{
					if (debug > 1) lprintf("resource_action %p\n", session->resource->doAction);
					session->resource->doAction(session);
					}
				break;
				}
			}
		}
	}

static void ci_session_closeAll(struct ci_module *ci)
{
	struct ci_session *session;
	int i;

	for (i = 0; i < MAX_SESSIONS; i++) {
		session = &ci->session[i];

		if (session->state != unused) {
			if (debug > 0) lprintf("session %d (%x) should be closed\n", session->index, session->resid);

			if (session->resource)
				if (session->resource->doClose)
					session->resource->doClose(session);

			/* check if private_data was removed */
			if (session->private_data)
				if (debug > 0) lprintf("cleanup of session %d failed\n", session->index);

			session->state = unused;
		}
	}
}

static bool ci_resource_register(struct ci_module *ci, const struct ci_resource *res)
{
	unsigned int i;

	for (i = 0; i < MAX_RESOURCES; i++) {
		if (!ci->resources[i]) {
			if (res->init && !res->init()) {
				if (debug > 0) lprintf("init for resource %#x failed\n", res->id);
				return false;
			}
			ci->resources[i] = res;
			return true;
		}
	}

	if (debug > 0) lprintf("resources are full\n");
	return false;
}

static void ci_fop_read(struct ci_module *ci)
{
	uint8_t recv_buf[RCV_SIZE];
	ssize_t recv_len;

	recv_len = read(ci->fd, recv_buf, RCV_SIZE);
	if (recv_len < 0) {
		if (debug > 0) lprintf("device read failed %d\n", recv_len);
		return;
	}

	if (debug > 4) lprintf("RECEIVED DATA ...\n");
	if (debug > 4) hexdump(recv_buf, recv_len);

	ci_session_receivedata(ci, recv_buf, recv_len);
}

static void ci_event(struct ci_module *ci, uint32_t events)
{
	if (events & EPOLLPRI) {
		if (ci->slot_state != 0) {
			ci->slot_state = 0;
			if (debug > 0) lprintf("module removed\n");
			if (fifo_pipe)
				{
				/* reset FIFO */
				write_fifo(0);
				last_access=0;
				current_access=0;
				}
			ci_session_closeAll(ci);
			socket_exit(ci->camd_socket, ci->slot_index);
			ci->camd_socket = -1;
			ci->res_camgr_ready = 0;
			ci->res_ccmgr_ready = 0;
			ci->res_ccmgr_timeout = 0;
			ci->app_name[0] = 0;
			idle=1;

        		/* remove the CI name file */
			remove_name_file(ci_name_underscore);

			ci_name[0]=0;
			ci_name_underscore[0]=0;
			if (ci->mmi_connected)
				mmi_set_appname(ci);
		}
		return;
	}

	if (ci->slot_state != 1) {
		ci->slot_state = 1;
		if (debug > 0) lprintf("\n");
		if (debug > 0) lprintf("CI%d module detected\n", ci_number);
		idle=0;
		if (fifo_pipe)
			{
		        if (debug > 9) lprintf("CI%d FIFO MODULE RESET\n",ci_number);
			fifo_time=time(NULL);
			fifo_named=0;
			fifo_handler=0;
			}
	}

	if (events & EPOLLIN) {
		if (debug > 10) lprintf(">>>>>> CI pollin\n");
		ci_fop_read(ci);
		return;
	}

	if (events & EPOLLOUT) {
		if (debug > 10) lprintf(">>>>>> CI pollout\n");
		ci_session_dequeue(ci);
		return;
	}
}

static const struct ci_resource resource_manager1 = {
        .id = 0x10041,
        .receive = ci_resmgr_receive,
        .doAction = ci_resmgr_doAction,
};

static const struct ci_resource resource_manager2 = {
        .id = 0x10042,
        .receive = ci_resmgr_receive,
        .doAction = ci_resmgr_doAction,
};

static int slot_index_from_device(const char *device)
{
	char *path;
	size_t len;
	int slot;

	path = realpath(device, NULL);
	if (path == NULL) /* will fail if device is captured by enigma2 */
		{
		if (debug > 0) lprintf("CI%d FAILED opening %s with %s\n",ci_number, device,strerror(errno));
		return -1;
		}

	len = strlen(path);
	if (len == 0)
		return -1;

	if (!isdigit(path[len - 1]))
		return -1;
	
	slot=path[len - 1] - '0';
	if (debug > 0) lprintf("CI%d DEVICE %d\n",ci_number, slot);

	return slot;
}

void ci_module_reset()
{
struct ci_module *ci_local;
	ci_local=&ci;

	if (debug > 4) lprintf("CI%d RESETTING\n", ci_number);
	if (ioctl(ci_local->fd, CA_RESET, 0))
           {
	   if (debug > 9) lprintf("CI%d CA_RESET failed %s\n", ci_number, strerror(errno));
           }
}

static bool ci_module_init(struct ci_module *ci, const char *device)
{
	unsigned int i;
	int start;
        FILE *settings;
	char line[256];
	char cfg[256];
	int cfg_len;

	memset(ci, 0, sizeof(struct ci_module));
	ci->camd_socket = -1;
	ci->mmi_socket = -1;
	ci->slot_index = slot_index_from_device(device);

	sprintf(cdev,"/dev/ci%d",ci->slot_index);
	sprintf(pdev,"/dev/plusci%d",ci->slot_index);

	if (fifo_pipe)
		{
		create_fifo();
		}

	start=1;
	sprintf(cfg,"config.ci.%d.start=false",ci_number);
	cfg_len=strlen(cfg);
     	settings = fopen("/etc/enigma2/settings", "rb");
	if (settings)
		{
		/* read a line */ 
 		while ( fgets ( line, sizeof(line), settings ) != NULL ) 
			{
       			if (strncmp(line,cfg,cfg_len) == 0) 
				{
				start=0;
				}
			}
    	       	fclose(settings);
		}

	if (!start)
		{
		fprintf(stdout, "\n   DISABLED CI%d\n", ci_number);
		fprintf(stdout, "\n");
		if (debug > 0) lprintf("CI%d DISABLED\n", ci_number);
		return 1;
		}

	if (fifo_pipe) /* open CI device and FIFO to enigma2 */
		{
		ci->fd = open(pdev, O_RDWR | O_NONBLOCK | O_CLOEXEC);
		if (ci->fd < 0) 
			{
			fprintf(stdout, "\n[DCP] FAILED CI%d: %s %s\n", ci_number, pdev, strerror(errno));
			fprintf(stdout, "\n");
			if (debug > 0) lprintf("CI%d FAILED: %s %s\n", ci_number, pdev, strerror(errno));
			return 1;
			}
		else
			{
			if (debug > 0) lprintf("CI%d OPENED: %s\n", ci_number, pdev);
			}
		fifo = open(cdev, O_RDWR | O_NONBLOCK | O_CLOEXEC );
		if (fifo < 0) 
			{
			fprintf(stdout, "\n[DCP] FIFO PIPE FAILED CI%d: %s %s\n", ci_number, cdev, strerror(errno));
			fprintf(stdout, "\n");
			if (debug > 0) lprintf("CI%d FAILED: %s %s\n", ci_number, cdev, strerror(errno));
			return 1;
			}
		else
			{
			if (debug > 0) lprintf("CI%d OPENED: %s\n", ci_number, cdev);
			}
		}
	else    	
		{
	   	/* open only CI device */
	   	ci->fd = open(cdev, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	   	if (ci->fd < 0) 
			{
			fprintf(stdout, "\n[DCP] FAILED CI%d: %s %s\n", ci_number, cdev, strerror(errno));
			fprintf(stdout, "\n");
			if (debug > 0) lprintf("CI%d FAILED: %s %s\n", ci_number, cdev, strerror(errno));
			return 1;
			}
   		else
			{
			if (debug > 0) lprintf("CI%d OPENED: %s\n", ci_number, cdev);
			}
		}
		
	ci->epoll = epoll_create1(EPOLL_CLOEXEC);
	if (ci->epoll < 0) {
		if (debug > 0) lprintf("epoll_create error!");
		return 1;
	}

	for (i = 0; i < MAX_SESSIONS; i++) {
		struct ci_session *session = &ci->session[i];
		session->slot_index = ci->slot_index;
		session->ci = ci;
		session->index = i + 1;
		session->state = unused;
	}
	if (debug > 0) lprintf("CI%d INIT OK\n", ci->slot_index);

	return 0;
}

static void timer_event(int fd, uint32_t events)
{
	uint64_t exp;
	ssize_t ret;

	if (events & EPOLLIN) {
		ret = read(fd, &exp, sizeof(uint64_t));
		if (ret < 0)
			{
			if (debug > 0) lprintf("read error: %s\n",strerror(errno));
			}
	}
}

static void return_ci(int sig) 
    {
    int restart_cmd=NONE;

    fprintf(stderr, "\n");
    if (!standalone)
        foreground=1;
    switch (sig) {
    case SIGBUS:
        if (debug > 0) lprintf("CI%d BUS ERROR ...\n",ci_number);
	restart_cmd=RESTART;
	break;
    case SIGILL:
        if (debug > 0) lprintf("CI%d ILLEGAL INSTRUCTION ...\n",ci_number);
	restart_cmd=RESTART;
	break;
    case SIGSEGV:
        if (debug > 0) lprintf("CI%d SEGMENT VIOLATION ...\n",ci_number);
	restart_cmd=RESTART;
	break;
    case SIGHUP:
	if (foreground)
		{
        	if (debug > 0) lprintf("CI%d HANGUP ...\n",ci_number);
		}
	else
		{
        	if (debug > 0) lprintf("CI%d IGNORED HANGUP ...\n",ci_number);
		return;
		}
	break;
    case SIGQUIT:
        if (debug > 0) lprintf("CI%d QUIT ...\n",ci_number);
	break;
    case SIGINT:
	if (foreground)
		{
	        if (debug > 0) lprintf("CI%d INTERRUPT ...\n",ci_number);
		}
	else
		{
        	if (debug > 0) lprintf("CI%d IGNORED INTERRUPT ...\n",ci_number);
		return;
		}
	break;
    case SIGABRT:
        if (debug > 0) lprintf("CI%d ABORT ...\n",ci_number);
	break;
    case SIGTERM:
	if (foreground)
		{
	       	if (debug > 0) lprintf("CI%d TERMINATE ...\n",ci_number);
		}
	else
		{
        	if (debug > 0) lprintf("CI%d IGNORED TERMINATE ...\n",ci_number);
		return;
		}
	break;
    case SIGRESTART:
        if (debug > 0) lprintf("CI%d RESTART ...\n",ci_number);
	restart_cmd=RESTART;
	break;
    case SIGCHLD:
	if (foreground)
		{
        	if (debug > 0) lprintf("CI%d CHILD ...\n",ci_number);
		}
	else
		{
        	if (debug > 0) lprintf("CI%d IGNORED CHILD ...\n",ci_number);
		return;
		}
	break;
    default:
        if (debug > 0) lprintf("CI %d EXIT ...\n",ci_number);
	break;
    }

    /* remove the service file */
    remove_service_file();

    /* remove the caid file */
    remove_caid_file();

    /* remove the PIN file */
    char pinfilename[32];
    sprintf(pinfilename,"/var/run/ca/dreamciplus%d.pin",ci_number);
    remove_pid(pinfilename);

    /* remove the CI name file */
    remove_name_file(ci_name_underscore);

    if (quiet) /* remove the auth file */
	{
        char source[32];
        sprintf(source, "ci_auth_slot_%d.bin", ci_number);
        char classicpath[256];
        sprintf(classicpath,"/var/run/ca/%s", source);
	remove(classicpath);
	}

    sync();

    if (fifo_pipe && fifo > 0)
	{
    	/* reset FIFO */
        if (debug > 9) lprintf("CI%d FIFO EXIT RESET\n",ci_number);
	write_fifo(0);
	fifo_time=0;
	fifo_handler=0;
	last_access=0;
	current_access=0;
	}

    if (resetting)
	{
    	/* reset the CI on exit */
    	ci_module_reset();
	}

    if (epoll_ctl(ci.epoll, EPOLL_CTL_DEL, ci.mmi_socket, NULL) < 0) 
	{
	if (debug > 9) lprintf("EPOLL_CTL_DEL MMI error\n");
	}
    if (epoll_ctl(ci.epoll, EPOLL_CTL_DEL, ci.fd, NULL) < 0) 
	{
	if (debug > 9) lprintf("EPOLL_CTL_DEL CI error\n");
	}
    if (epoll_ctl(ci.epoll, EPOLL_CTL_DEL, ci.camd_socket, NULL) < 0) 
	{
	if (debug > 9) lprintf("EPOLL_CTL_DEL CAMD error\n");
	}
    /* close everything is now here */
    if (fifo_pipe)
	{
    	close(fifo);
	}

    close(timerfd);
    close(ci.mmi_socket);
    close(ci.fd);
    close(ci.camd_socket);
    close(ci.epoll);
    descrambler_deinit();

    char socketfilename[32];
    sprintf(socketfilename,"/var/run/ca/ci%d.socket",ci_number);
    remove(socketfilename);

    sync();

    /* remove the pidfile */
    char pidfilename[32];
    FILE *pid_file;
    sprintf(pidfilename,"/var/run/ca/dreamciplus%d.pid",ci_number);
    pid_file = fopen(pidfilename, "r");
    if (pid_file)
	{
	fclose(pid_file);
	remove_pid(pidfilename);
	}

    /* final chance to start again ... */
    if (restart_cmd==RESTART || sig == SIGRESTART) 
	{
	if (debug > 9) lprintf("CI%d RESTARTING ...\n",ci_number);
	dreamciplus(NONE,ci_number);
	}

    if (debug > 0)
        {
        lprintf("CI%d FINISHED\n", ci_number);
        }
    else
        {
        fprintf(stderr, "\n");
        }
    if (standalone)
	exit(0); 

    /* suicide */
    pid_t current_pid=0;	
    current_pid=getpid();
    if (current_pid > 0)
	   {
	   kill(current_pid, 9);
	   }
    return;
}

static void mmi_set_appname(struct ci_module *ci)
{
	char setname[4 + 4 + 3 + sizeof(ci->app_name)] = "\x1\x2\x3\x4";
	unsigned int pos = 4;

	pos += snprintf(&setname[pos], sizeof(setname) - pos, "CI %u", ci->slot_index + 1);
	if (strlen(ci->app_name) > 0)
		pos += snprintf(&setname[pos], sizeof(setname) - pos, " %s", ci->app_name);
	ci_mmi_enqueue(ci, (const uint8_t *)setname, pos);
}

static int mmi_event(struct ci_module *ci, int fd, uint32_t events)
{
	int entered_pin=0;
	if (debug > 10) lprintf("HANDLE MMI event: %x\n", events);

	if ((events & (EPOLLIN | EPOLLHUP)) == (EPOLLIN | EPOLLHUP)) {
		if (debug > 0) lprintf("MMI hangup\n");
		ci->mmi_connected = false;
		return -1;
	}

	if ((events & EPOLLOUT) == EPOLLOUT) {
		if (!ci->mmi_connected) {
			if (debug > 0) lprintf("MMI new connection\n");
			mmi_set_appname(ci);
			ci->mmi_connected = true;
			}
		ci_mmi_dequeue(ci);
	}

	if (events & EPOLLIN) {
		struct ci_session *session = NULL;
		unsigned char buf[8192];
		ssize_t len;

		if (debug > 9) lprintf("MMI data\n");

		len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (len < 0) {
			if (debug > 0) lprintf("recv error: %s\n",strerror(errno));
			return -1;
		}
		if (debug >4) hexdump(buf, len);
		if (len == 0)
			{
			if (debug > 9) lprintf("MMI no data\n");
			return -1;
			}
		else
			{
			if (debug > 9) lprintf("MMI processing data\n");
			}
		if (buf[0] == 0x9f && buf[1] == 0x80 && buf[2] == 0x22)
			{
			if (debug > 9) lprintf("MMI enter menu\n");
			session = ci_session_by_resource_id(ci, 0x20043);
		        if (session == NULL) /* fallback */
			    {
			    session = ci_session_by_resource_id(ci, 0x20041);
			    }
			}

		else if (buf[0] == 0x9f && buf[1] == 0x80 && (buf[2] & 0xf0) == 0x20)
			{
			if (debug > 9) lprintf("MMI application info enq\n");
			session = ci_session_by_resource_id(ci, 0x20043);
		        if (session == NULL)
			    {
			    session = ci_session_by_resource_id(ci, 0x20041);
			    }
			}
		else if (buf[0] == 0x9f && buf[1] == 0x88)
			{
			/* check for CA_ message */
			if (buf[2] == 0x08 && (buf[3] == 0x08 || buf[3] == 0x09 || buf[3] == 0x0b) && buf[4] == 0x01)
				{
				/* check for CA_ */
				if (buf[5] == 0x43 && buf[6] == 0x41 && buf[7] == 0x5f)
					{
					switch (buf[8])
					    {
					    case 'R':
						{ 
						if (buf[11]==69) /* CA_R(ESET) */
						{
						if (debug > 0) lprintf("CI%d CA_RESET\n", ci_number);
						reset_auth(ci_number);
						resetting=1;
						return_ci(SIGRESTART);
						}
						if (buf[11]==84) /* CA_R(ESTART) */
						{
						if (debug > 0) lprintf("CI%d CA_RESTART\n", ci_number);
						return_ci(SIGRESTART);
						}
						break;
						}
					    case 'I':
						{ /* CA_I(INIT) */
						if (debug > 0) lprintf("CI%d CA_INIT\n", ci_number);
						resetting=1;
						return_ci(SIGRESTART);
						break;
						}
					    case 'K':
						{ /* CA_K(ILL) */
						if (debug > 0) lprintf("CI%d CA_KILL\n", ci_number);
						return_ci(0);
						break;
						}
					default:
						break;
					}
				    }
				}
			if (len == 9 && buf[0] == 0x9f && buf[1] == 0x88 && buf[2] == 0x08 && buf[3] == 0x05 && buf[4] == 0x01)
					{
					buf[9]=0;
					entered_pin=atol((const char *) buf+5);
					if (debug > 0) lprintf("ENTERED PIN ....\n");
    					char pinfilename[32];
    					sprintf(pinfilename,"/var/run/ca/dreamciplus%d.pin",ci_number);
					write_pid(pinfilename,entered_pin);
					}
			/* handle real MMI message */
			session = ci_session_by_resource_id(ci, 0x400041);
			}

		if (session != NULL)
			{
			if (debug > 0) lprintf("CI%d session not NULL\n", ci_number);
			ci_session_sendSPDU_A(ci, 0x90, buf, len, session->index);
			}
		else 
			{
			if (debug > 0) lprintf("CI%d session is NULL, bad news\n", ci_number);
			}
	}

	return 0;
}

static int mmi_init(void)
{
	struct sockaddr_un addr;
	int fd;

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, "/tmp/mmi.socket");

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		if (debug > 0) lprintf("mmi socket error: %s\n",strerror(errno));
		return -1;
	}

//	if (debug > 9 && connect_mmi) lprintf("MMI connecting\n");

	if (connect(fd, (const struct sockaddr *)&addr, SUN_LEN(&addr)) < 0) {
		if (debug > 0) lprintf(".");
		close(fd);
//		usleep(10000);
		return -1;
	}
        return fd;                      
}

void version(FILE *output)
  {
  if (uname(&u) != 0)
           {
           if (debug > 9) lprintf("KERNEL unknown\n");
	   u.release[0]=0;
	   u.nodename[0]=0;
	   }
  fprintf(output,KBLU"\ndreamciplus V%d.%d Slots #%d Build %s %s\n\n***** Kernel %s Architecture %s *****\n\n"KNRM, v1,v2,max_ci,__DATE__,__TIME__,u.release,u.machine);
  return;
  }

int dreamciplus(int command, int slot)
{
        FILE *settings;
        FILE *pid_file;
	FILE *service_file;
	FILE *ll;
	int null;
	int tmp;
	char ci_dev[256];
	char line[256];
	char cfg[256];
	int cfg_len;
	int ret=0;
	int pid;
        char pidfilename[32];

	/* reset after restart */
	oldpids[0]=0;
	cachedpids[0]=0;
	demux_device[0]=0;
	old_buf_tuner[0]=0;
	old_buf_device[0]=0;
	old_buf_module[0]=0; 
	fullserviceref[0]=0;
	currentref[0]=0;;
	oldpids[0]=0;      
	pid_t current_pid=0;	
	descrambles=0;
	assigned=0;
	current=0;

	/* initalize authie with "/tmp/ " */
	authie[0]=47;
	authie[1]=116;
	authie[2]=109;
	authie[3]=112;
	authie[4]=47;
	authie[5]=32;
	authie[6]=0;
	/* initalize devie with "/dev/ " */
	devie[0]=47;
	devie[1]=100;
	devie[2]=101;
	devie[3]=118;
	devie[4]=47;
	devie[5]=32;
	devie[6]=0;

	bool running = true;
	struct epoll_event ev;
	uint32_t ci_events = EPOLLIN | EPOLLPRI;
	uint32_t mmi_events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR;
	const struct itimerspec ts = { { 0, 100000000 }, { 0, 10000000 } };

        if (uname(&u) != 0)
           {
           if (debug > 9) lprintf("KERNEL unknown\n");
	   u.release[0]=0;
	   u.nodename[0]=0;
	   }

   	sprintf(logfile,"/tmp/dreamciplus%d.log",slot);
	/* count number of CI slots */
	max_ci=count_files("/dev", "ci");

	char vu[3];
	vu[0]=118;
	vu[1]=117;
	vu[2]=0;
  	if (strncmp(u.nodename,vu,2)==0) max_ci=1;  /* no comment */

	/* make passed parameters global */
	ci_number=slot;
        ci_command=command;
        sprintf(ci_dev,"/dev/ci%d",slot);

	mkdir("/var/run/ca", 0777);
 	dreambox=strstr(u.release,"dm");                                                  
        /* mmi socket could be also disabled via settings */
	if (connect_mmi)
	   {
     	   settings = fopen("/etc/enigma2/settings", "rb");
	   if (settings)
	      {
	      sprintf(cfg,"config.ci.%d.mmi=true",slot);
	      cfg_len=strlen(cfg);
	      /* read a line */ 
 	      while ( fgets ( line, sizeof(line), settings ) != NULL ) 
		{
                if (strncmp(line,cfg,cfg_len) == 0) 
		   {
		   connect_mmi=0;
		   }
		 }
       	      fclose(settings);
       	      }
           }

        /* autopin could be also enabled via settings */
	if (autopin)
	   {
     	   settings = fopen("/etc/enigma2/settings", "rb");
	   if (settings)
	      {
	      sprintf(cfg,"config.ci.%d.autopin=true",slot);
	      cfg_len=strlen(cfg);
	      /* read a line */ 
 	      while ( fgets ( line, sizeof(line), settings ) != NULL ) 
		{
                if (strncmp(line,cfg,cfg_len) == 0) 
		   {
		   autopin=1;
		   }
		 }
       	      fclose(settings);
       	      }
           }

        /* classic could be also enabled via settings */
	if (autopin)
	   {
     	   settings = fopen("/etc/enigma2/settings", "rb");
	   if (settings)
	      {
	      sprintf(cfg,"config.ci.%d.classic=true",slot);
	      cfg_len=strlen(cfg);
	      /* read a line */ 
 	      while ( fgets ( line, sizeof(line), settings ) != NULL ) 
		{
                if (strncmp(line,cfg,cfg_len) == 0) 
		   {
		   classic=1;
		   }
		 }
       	      fclose(settings);
       	      }
           }

        /* quiet could be also disabled via settings */
	if (quiet)
	   {
     	   settings = fopen("/etc/enigma2/settings", "rb");
	   if (settings)
	      {
	      sprintf(cfg,"config.ci.%d.quiet=false",slot);
	      cfg_len=strlen(cfg);
	      /* read a line */ 
 	      while ( fgets ( line, sizeof(line), settings ) != NULL ) 
		{
                if (strncmp(line,cfg,cfg_len) == 0) 
		   {
		   quiet=0;
		   }
		 }
       	      fclose(settings);
       	      }
           }

     	/* FIFO pipe could be also disabled via settings */
	if (fifo_pipe)
	   {
     	   settings = fopen("/etc/enigma2/settings", "rb");
	   if (settings)
	      {
	      sprintf(cfg,"config.ci.%d.plus=false",slot);
	      cfg_len=strlen(cfg);
	      /* read a line */ 
 	      while ( fgets ( line, sizeof(line), settings ) != NULL ) 
		{
               	if (strncmp(line,cfg,cfg_len) == 0) 
	   		{
	   		fifo_pipe=0;
	   		}
	 	}
       	      fclose(settings);
              }
           }
     	service_file = fopen("/lib/systemd/system/dreamciplus.service", "r");
       	if (service_file)      
                {                          
                fclose(service_file);        
		remove(dream_ci_legacy1);
		remove(dream_ci_legacy2);
		remove(dream_ci_legacy3);
		remove(dream_ci_legacy4);
		}
	else
	   	{
	   	remove("/etc/rcS.d/S66dreamciplus");
		remove("/etc/rc6.d/K66dreamciplus");
		remove("/etc/rc1.d/K66dreamciplus");
		remove("/etc/rc0.d/K66dreamciplus");
		remove(dream_ci_legacy5);
		}			 
	/* check and correct architecture symlink */
     	settings = fopen(dream_ci_so, "rb");
	if (settings) /* architecture symlink exists */
	        {
		fclose(settings);
		}
	 else         /* architecture symlink missing */
		{
               	if (!strcmp(u.machine,"mips"))
                      {
                      ret=symlink(dream_ci_so_mipsel,dream_ci_so);
                      if (ret)
                             {
                             if (debug > 0) lprintf("symlink error ...\n");
                             }
                      }
              	else
                      {
                      ret=symlink(dream_ci_so_armhf,dream_ci_so);
               	      if (ret)
                             {
                             if (debug > 0) lprintf("symlink error ...\n");
                             }
                      }
                }
	struct stat st;
        if (!strcmp(u.machine,"mips"))
		{
               	settings = fopen(dream_ci_so_armhf, "rb");
                if (settings)
		    {
		    fclose(settings);
		    stat(dream_ci_so_armhf, &st);
		    if (st.st_size > 0)
			{
                       	/* replace unneeded armhf with empty file */
                       	remove(dream_ci_so_armhf);
                       	open (dream_ci_so_armhf, O_RDWR|O_CREAT,0);
		   	}
		    }
	        }
	else
                {
               	settings = fopen(dream_ci_so_mipsel, "rb");
               	if (settings)
		    {
		    fclose(settings);
		    stat(dream_ci_so_mipsel, &st);
		    if (st.st_size > 0)
			{
                      	/* replace unneeded mipsel with empty file */
                       	remove(dream_ci_so_mipsel);
                       	open (dream_ci_so_mipsel, O_RDWR|O_CREAT,0);
		   	}
		     }
	         }

        /* logging could be also enabled via settings */
	if (!logging && !debug)
	   {
     	   settings = fopen("/etc/enigma2/settings", "rb");
	   if (settings)
	      {
	      sprintf(cfg,"config.ci.%d.logging=true",slot);
	      cfg_len=strlen(cfg);
	      /* read a line */ 
 	      while ( fgets ( line, sizeof(line), settings ) != NULL ) 
		{
                if (strncmp(line,cfg,cfg_len) == 0) 
		   {
		   logging=1;
		   /* settings use full debug and default logfile */
		   debug=10;
		   sprintf(logfile,"/tmp/dreamciplus%d.log",slot);
		   }
		 }
       	      fclose(settings);
       	      }
           }

     	ll = fopen(logfile, "r");
	if (ll) 
	        {
	   	fclose(ll);
		remove(logfile);
		}
 	FILE *logout;
        if (logging)
           {
	   if (debug > 10) lprintf("CI%d LOGFILE: %s\n",slot, logfile);
           logout = fopen(logfile, "a");
           if (logout > 0)
              {
              version(logout);
              fclose(logout);
              }
	   else
              {
	      /* fall back to default logfile */
	      if (debug > 0) lprintf("[DCP] LOGFILE: %s error: %s\n",logfile, strerror(errno));
	      sprintf(logfile,"/tmp/dreamciplus%d.log",slot);
   	      fprintf(stderr,"[DCP] USING LOGFILE: %s\n",logfile);
     	      ll = fopen(logfile, "r");
	      if (ll) 
	   	{
	   	fclose(ll);
		remove(logfile);
		}
              logout = fopen(logfile, "a");
              if (logout > 0)
                 {
		 version(logout);
                 fclose(logout);
                 }
              }
	   if (debug > 0) lprintf("DEBUGGING level %d ...\n", debug);
	   if (debug > 0) lprintf("LOGGING to %s ...\n", logfile);
	   }
	else
           {
	   if (debug > 0) lprintf("DEBUGGING level %d ...\n", debug);
	   }

        if (dreambox == NULL)
           { 
  	   dreambox=u.nodename; 
           if (debug > 0) lprintf("ALIEN %s ...\n", dreambox);
	   fifo_pipe=1; /* aliens always use fifo pipe */
	   }
	else
           { 
           if (debug > 0) lprintf("DREAMBOX %s ...\n", dreambox);
	   }

	if (debug > 10) 
		{
		lprintf("TIMER INTERVAL %lld.%.9ld\n", (long long)ts.it_interval.tv_sec, ts.it_interval.tv_nsec);
		lprintf("TIMER EXPIRATION %lld.%.9ld\n", (long long)ts.it_value.tv_sec, ts.it_value.tv_nsec);
		}

	if (debug > 0) 
		{
                if (fifo_pipe) 
			{
  			lprintf("PLUS ENABLED\n");
			}
		else
			{
  			lprintf("PLUS DISABLED\n");
			}
                if (connect_mmi) 
			{
  			lprintf("MMI ENABLED\n");
			}
		else
			{
  			lprintf("MMI DISABLED\n");
			}
                if (autopin) 
			{
  			lprintf("AUTOPIN ENABLED\n");
			}
                if (classic) 
			{
  			lprintf("CLASSIC ENABLED\n");
			}
		if (!bcd_time)
			{
			lprintf("BCD TIME DISABLED\n");
			}
		if (extract_ci_cert)
			{
			lprintf("EXTRACTING ENABLED\n");
			}
		}

	/* tune the socket buffers ... a little bit ... */
	write_proc();

	sprintf(pidfilename,"/var/run/ca/dreamciplus%d.pid",slot);

	/* handle commands */
	switch (ci_command)
		{
		case NONE:
		if (debug > 0) lprintf("CI%d starting NORMAL\n",ci_number);
		if (standalone)
		   {
		   foreground=1;
		   }
		else /* swap  devices with enigma2 */
		   {
		   sprintf(cdev,"/dev/ci%d",ci_number);
		   sprintf(cdev2,"/dev/ci%d",!ci_number);
		   sprintf(pdev,"/dev/plusci%d",ci_number);
		   sprintf(pdev2,"/dev/plusci%d",!ci_number);
		   if (fifo_pipe)
			{
			/* create fifo to avoid enigma2 opening */
			create_fifo();
			}
     		enigma2_pid=getpid();
		/* we have to check pdev due to above create fifo 
		   which renamed cdev to pdev and created cdev as fifo */
     		tmp=file_opened(pdev, enigma2_pid);
		if (tmp > 0)
	        	{
			if (debug > 10) lprintf("ENIGMA2 %d OPENED %s %d\n",enigma2_pid,pdev,tmp);
			/* replace enigma2 ci dev with fifo */
        		ret = dup(tmp);
        		close(tmp);
			null = open(cdev, O_RDWR | O_NONBLOCK | O_CLOEXEC);
        		dup2(null, tmp);
                        close(ret);
			}

		current_pid = fork(); /* now we have swapped devices 
					 and can start own process */
		if(current_pid == 0) 
		        {
			if (debug > 9) lprintf("CI%d EXECUTES ...\n", ci_number);
			/* child has inherited also other ci device
			   from enigma2 which needs to be closed to 
			   prevent problems */
     			current_pid=getpid();
     			tmp=file_opened(cdev2, current_pid);
			if (tmp > 0)
	        		{
				close(tmp);
				}
            		}
        	else 
            	        {
	    		/* successfull return of main thread */
            		return 0;
            		}
            	}
			break;
		case START:
			if (foreground)
				{
				if (debug > 0) lprintf("CI%d starting FOREGROUND\n",ci_number);
				}
			else
				{
				if (debug > 0) lprintf("CI%d starting DAEMON\n",ci_number);
				ret=daemon(0,0);
                		if (ret)
                       			{
                        		if (debug > 0) lprintf("daemon error ...\n");
                        		}
				}
			break;
		case STOP:
     	   		pid_file = fopen(pidfilename, "r");
	   		if (pid_file)
	      			{
				fclose(pid_file);
				pid=read_pid(pidfilename);
				if (pid > 0)
					{
					if (debug > 0) lprintf("CI%d STOPPING pid %d\n",ci_number, pid);
					kill(pid, SIGABRT);
				//	printf("\n");
					exit(0);
					}
				}
			if (debug > 0) lprintf("CI%d nothing to STOP\n",ci_number);
			exit(0);
			break;
		case RESTART:
     	   		pid_file = fopen(pidfilename, "rb");
	   		if (pid_file)
	      			{
				fclose(pid_file);
				pid=read_pid(pidfilename);
				if (pid > 0)
					{
					if (debug > 0) lprintf("CI%d STOPPING pid %d\n",ci_number, pid);
					kill(pid, SIGABRT);
				//	printf("\n");
					}
				}
			/* allow a few seconds to free device file */
			sleep(3);
			if (foreground)
				{
				if (debug > 0) lprintf("CI%d starting FOREGROUND\n",ci_number);
				}
			else
				{
				if (debug > 0) lprintf("CI%d starting DAEMON\n",ci_number);
				ret=daemon(0,0);
                		if (ret)
                       			{
                        		if (debug > 0) lprintf("daemon error ...\n");
                        		}
				}
			break;
			}

	/* last exit Brooklyn */
        signal(SIGINT,   return_ci);
        signal(SIGHUP,   return_ci);
        signal(SIGQUIT,  return_ci);
        signal(SIGABRT,  return_ci);
        signal(SIGTERM,  return_ci);
        signal(SIGILL,   return_ci);
        signal(SIGBUS,   return_ci);
        signal(SIGSEGV,  return_ci);
        signal(SIGCHLD,  return_ci);

	/* prevent crashing when uninitialized after Standby */
	old_buf_tuner[0]=0;
	old_buf_device[0]=0;
	old_buf_module[0]=0;
	fullserviceref[0]=0;
	currentref[0]=0;;

	/* nothing really happened until now */

        if (!check_enigma2())
	   {
	   camd_open=1;
	   }
	else
	   {
	   camd_client=0;
	   }

	if (descrambler_init()) return 1;

	/* intialize local structs */
	if (ci_module_init(&ci, ci_dev)) return 1;

	if (resetting)
		{
    		/* reset the CI on startup */
    		ci_module_reset();
		}

        remove_service_file();

	/* looks good, let us handle the pidfile */
	write_pid(pidfilename,0);

        /* remove the PIN file */
        char pinfilename[32];
        sprintf(pinfilename,"/var/run/ca/dreamciplus%d.pin",ci_number);
        remove_pid(pinfilename);

	/* init the local resource manager */
	ci_resource_register(&ci, &resource_manager1); 
	ci_resource_register(&ci, &resource_manager2);

	/* install all available resources */
	ci_resource_register(&ci, &resource_app_info1);
	ci_resource_register(&ci, &resource_app_info2);
	ci_resource_register(&ci, &resource_app_info3);
	ci_resource_register(&ci, &resource_ca_support);
	ci_resource_register(&ci, &resource_host_ctrl1);
	ci_resource_register(&ci, &resource_host_ctrl2);
	ci_resource_register(&ci, &resource_datetime);
	ci_resource_register(&ci, &resource_mmi);
	ci_resource_register(&ci, &resource_app_mmi1);
	ci_resource_register(&ci, &resource_app_mmi2);
	ci_resource_register(&ci, &resource_content_ctrl1);
#ifdef BAD
	ci_resource_register(&ci, &resource_content_ctrl2);
#endif
 	ci_resource_register(&ci, &resource_host_lac); 
 	ci_resource_register(&ci, &resource_cam_upgrade);

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = ci_events;
	ev.data.fd = ci.fd;

	if (epoll_ctl(ci.epoll, EPOLL_CTL_ADD, ci.fd, &ev) < 0) {
      		if (debug > 0) lprintf("EPOLL_CTL_ADD ci error: %s\n",strerror(errno));
		return_ci(1);
	}

	timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (timerfd < 0) {
		if (debug > 0) lprintf("timerfd_create");
		return_ci(1);
	}

	if (timerfd_settime(timerfd, 0, &ts, NULL) < 0) {
		if (debug > 0) lprintf("timerfd_settime");
		return_ci(1);
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = timerfd;

	if (epoll_ctl(ci.epoll, EPOLL_CTL_ADD, timerfd, &ev) < 0) {
		if (debug > 0) lprintf("EPOLL_CTL_ADD error");
		return_ci(1);
	}

	/* main loop */
	while (running) {
		static const unsigned int MAX_EVENTS = 64;
		struct epoll_event events[MAX_EVENTS];
		int i, n;
		current_time=time(NULL);
		if (fifo_pipe && !fifo_time && (strlen(ci_name) > 0) && ci.camd_socket > 0)
			{ /* check also if enigma2 is already running */
			current_pid = GetPIDbyName("enigma2") ;
			if (current_pid > 0)
                		{
            		//	if (debug > 6) lprintf("CI%d enigma2 pid: %d\n",ci_number, current_pid);
				
 				/* check if enigma2 already opened the fifo */
				if (file_opened(cdev, current_pid)) 
					{ 
				        if (debug > 9) lprintf("CI%d START FIFO PIPE APP\n", ci_number);
					fifo_time=current_time;
					fifo_named=0;
					}
				}
			} 
		if (fifo_pipe && fifo_time && current_time > 60 && ((current_time - fifo_time) > 5 ) && ci.camd_socket > 0)
			{ /* send enigma2 the CI name */
			name_fifo(1);
			last_access=0;
			current_access=0;
			}

		n = epoll_wait(ci.epoll, events, MAX_EVENTS, -1);
		if (n < 0) 
			{
			if (debug > 10) lprintf("NO epoll_wait\n");
			}
		else
			{
			if (n > 1)
				{
				if (debug > 10) lprintf(">>>>>>>>>> EPOLL n: %d\n", n);
				}
			}
		/* reduce CPU load if idle */
		if (idle)
			usleep(10000);

		for (i = 0; i < n; i++) 
			{
			if (n > 1)
				{
				if (debug > 10) lprintf(">>>>>>>>>> HANDLE i: %d\n", i);
				}
			/* timer event */
			if (events[i].data.fd == timerfd) 
				{
				if (fifo_pipe)
				    {
				    if (!last_access && fifo_handler)
					{
					last_access=get_mtime(cdev)+1;
					if (debug > 10) lprintf(">>>>>>>>>> FIRST ACCESS: %d\n", (int)last_access);
					}
				    else
					{
					current_access=get_mtime(cdev);
					if (last_access && current_access > last_access)
						{
						if (debug > 10) lprintf(">>>>>>>>>> LAST %d NEW ACCESS: %d\n", (int)last_access, (int)current_access);
						last_access=current_access;
						struct ci_session *session = NULL;
						session = ci_session_by_resource_id(&ci, 0x20043);
					        if (session == NULL) /* fallback */
							{
			    				session = ci_session_by_resource_id(&ci, 0x20041);
			    				}
						if (debug > 9) lprintf("CI%d MENU REQUEST ...\n", ci_number);
				                uint8_t tag[4] = { 0x9f, 0x80, 0x22, 0x00};
						/* start MMI menu session */
						ci_session_sendSPDU_A(&ci, 0x90, tag, 4, session->index);
						}

					}
				    }
				timer_event(timerfd, events[i].events);
				if (ci.slot_state) 
					{
					if (ci.res_ccmgr_timeout > MAX_TIMEOUT) 
						{
						/* timeout */
						if (!ci.res_ccmgr_ready) 
							{
							if (debug > 9) lprintf("TIMEOUT ...\n");
							/* check if content_control session is available */
							struct ci_session *session = NULL;
							session = ci_session_by_resource_id(&ci, 0x8c1001);
							if (session == NULL)                                       
						                {                                                            
                   						if (debug > 9) lprintf("OVERRIDE session %d ...\n", session);
                   						ci.res_ccmgr_ready = 1; /* override */                       
                   						ci.res_ccmgr_timeout=0;                                      
                   						if (ci.res_camgr_ready)                                      
                           						start_camd_socket(&ci);                              
                   						}                                                            
						         else                                                                 
    						                {                                                          
						                if (debug > 9) lprintf("RESTART session %d ...\n", session); 
                   						ci_session_sendSPDU_A(&ci, 0x90, 0, 0, session->index);      
                   						ci.res_ccmgr_timeout=0;                                      
                   						}            
							}
						} 
					else 
						{
						/* waiting for timeout */
						if (debug > 10) lprintf("waiting: %d\n", ci.res_ccmgr_timeout);
						++ci.res_ccmgr_timeout;
						}
					}

				if (ci.mmi_socket < 0 && connect_mmi) 
					{
					ci.mmi_socket = mmi_init();
					if (ci.mmi_socket >= 0) 
						{
						memset(&ev, 0, sizeof(struct epoll_event));
						ev.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR;
						ev.data.fd = ci.mmi_socket;

						if (debug > 0) lprintf("\n");
						if (debug > 0) lprintf("MMI adding\n");
						if (epoll_ctl(ci.epoll, EPOLL_CTL_ADD, ci.mmi_socket, &ev) < 0) 
							{
							if (debug > 0) lprintf("EPOLL_CTL_ADD error\n");
							return_ci(1);
							}
			 			if (fifo_pipe)
							{
                					if (debug > 9) lprintf("CI%d FIFO MMI RESET\n",ci_number);
							/* reset time so that module name gets re-written to fifo */
							fifo_time=time(NULL); 
							fifo_named=0;
							fifo_handler=0;
							}

						}
					}
				} 
			/* CI event */
			else if (events[i].data.fd == ci.fd) 
				{
				ci_event(&ci, events[i].events);
				ci_session_pollAll(&ci);
				} 
			/* camd event */
			else if (ci.camd_socket >= 0 && events[i].data.fd == ci.camd_socket)
				{
			   	if (!camd_client) /* act as server = classic */
       	                        	{
					if (debug > 3) lprintf("Classic Server event\n");
					int fd = socket_server_event(ci.camd_socket, events[i].events);
					if (fd >= 0) 
						{
						memset(&ev, 0, sizeof(struct epoll_event));
						ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
						ev.data.fd = fd;
						/* FORGOTTEN */
						if (descrambles < 2)
							descrambles++;
						if (debug > 3) lprintf("Adding client\n");
	           				if (debug > 2) lprintf("CI%d DESCRAMBLES: %d ASSIGNED: %d\n",ci_number,descrambles, assigned);
						if (epoll_ctl(ci.epoll, EPOLL_CTL_ADD, fd, &ev) < 0) 
							{
							if (debug > 0) lprintf("EPOLL_CTL_ADD error\n");
							return_ci(1);
							}
						}
			        	}
			     	else
					{ /* act as client = open */
					if (debug > 3) lprintf("Open Client event\n");
					int ret = socket_client_event(events[i].data.fd, events[i].events);
					if (ret < 0) 
						{
						if (ret == -2)
							{ /* Client Hangup = restart */
							sleep(5);
							return_ci(SIGRESTART);
							}
						if (descrambles > 0)
							descrambles--;
						if (debug > 3) lprintf("Removing Open Client\n");
           					if (debug > 5) lprintf("CI%d DESCRAMBLES: %d ASSIGNED: %d\n",ci_number,descrambles,assigned);
						if (descrambles == 0)
							{
							/* remove the service file */
    							remove_service_file();
							}
						}	
					else    /* FORGOTTEN */
						{
						if (descrambles < 1)
							descrambles++;
           					if (debug > 5) lprintf("CI%d DESCRAMBLES: %d ASSIGNED: %d\n",ci_number,descrambles,assigned);
						}	
				    	}
				} 
			/* MMI event */
			else if (ci.mmi_socket >= 0 && events[i].data.fd == ci.mmi_socket) 
				{
				if (debug > 0) lprintf("MMI event\n");
				int ret = mmi_event(&ci, events[i].data.fd, events[i].events);
				if (ret < 0) 
					{
					if (debug > 2) lprintf("MMI removing\n");
					if (epoll_ctl(ci.epoll, EPOLL_CTL_DEL, events[i].data.fd, NULL) < 0) {
						if (debug > 0) lprintf("EPOLL_CTL_DEL error\n");
						return_ci(1);
					}
			 	if (fifo_pipe)
					{
					/* reset FIFO */
					write_fifo(0);
					last_access=0;
					current_access=0;
					}

				close(events[i].data.fd);
				ci.mmi_socket = -1;
				mmi_events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR;
				}
			} 
		else 
			{
			if (debug > 3) lprintf("Client event\n");
			int ret = socket_client_event(events[i].data.fd, events[i].events);
			if (ret < 0) 
				{
				if (debug > 3) lprintf("Removing Classic Client\n");
				if (descrambles > 0)
					descrambles--;
				if (debug > 5) lprintf("CI%d DESCRAMBLES: %d ASSIGNED: %d\n",ci_number,descrambles,assigned);
				if (descrambles == 0)
					{
					/* remove the service file */
					remove_service_file();
					}
				if (epoll_ctl(ci.epoll, EPOLL_CTL_DEL, events[i].data.fd, NULL) < 0) 
					{
					if (debug > 0) lprintf("EPOLL_CTL_DEL error\n");
					return_ci(1);
                                        }
//				close(events[i].data.fd);
				}
			}
		}

		memset(&ev, 0, sizeof(struct epoll_event));
		ev.events = EPOLLIN | EPOLLPRI;
		if (!list_empty(ci.txq))
			{ 
			if (debug > 10) lprintf(">>>>>> CI LEFTOVER\n");
			ev.events |= EPOLLOUT;
			}
		ev.data.fd = ci.fd;

		if (ci_events != ev.events) 
			{
			if (epoll_ctl(ci.epoll, EPOLL_CTL_MOD, ci.fd, &ev) < 0) 				{
		      		if (debug > 0) lprintf("EPOLL_CTL_MOD error: %s\n",strerror(errno));
				return_ci(1);
				}
			if (debug > 10) lprintf(">>>>>> CI FILLING EVENT\n");
			ci_events = ev.events;
			}

		if (ci.mmi_socket >= 0 && ci.mmi_connected) 
			{
			memset(&ev, 0, sizeof(struct epoll_event));
			ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
			if (!list_empty(ci.mmiq))
				{
				if (debug > 10) lprintf(">>>>>> MMI LEFTOVER\n");
				ev.events |= EPOLLOUT;
				}
			ev.data.fd = ci.mmi_socket;

			if (mmi_events != ev.events) 
				{
				if (epoll_ctl(ci.epoll, EPOLL_CTL_MOD, ci.mmi_socket, &ev) < 0) 		
					{
			      		if (debug > 0) lprintf("EPOLL_CTL_MOD error: %s\n",strerror(errno));
					return_ci(1);
					}
				if (debug > 10) lprintf(">>>>>> MMI FILLING EVENT\n");
				mmi_events = ev.events;
				}
			}
		}

	return_ci(0);
	return 1;
}

int getVersion()
	{
	version(stdout);
	return v1*100+v2;
	}

int start(int slot)
	{
        FILE *settings;
        FILE *pid_file;
	int start=1;
	char line[256];
	char cfg[256];
	int cfg_len;
	int pid=0;
	int ret=0;
        char pidfilename[32];
        char procfilename[32];
	ci_command=NONE; /* means start */
	/* count number of CI slots */
	max_ci=count_files("/dev", "ci");
	if (slot < max_ci)
		{
		settings = fopen("/etc/enigma2/settings", "rb");
   		if (settings)
      			{
			sprintf(cfg,"config.ci.%d.start=false",slot);
			cfg_len=strlen(cfg);
      			/* read a line */ 
      			while ( fgets ( line, sizeof(line), settings ) != NULL )
				{
  	     		        if (strncmp(line,cfg,cfg_len) == 0) 
			   		{
					start=0;
			   		}
			   	}
       		      	fclose(settings);
			}
		settings = fopen("/etc/enigma2/settings", "rb");
   		if (settings)
      			{
			sprintf(cfg,"config.ci.%d.plus=false",slot);
			cfg_len=strlen(cfg);
      			/* read a line */ 
      			while ( fgets ( line, sizeof(line), settings ) != NULL )
				{
  	     		        if (strncmp(line,cfg,cfg_len) == 0) 
			   		{
					start=0;
			   		}
			   	}
       		      	fclose(settings);
			}
		if (start)
			{
      			sprintf(pidfilename,"/var/run/ca/dreamciplus%d.pid",slot);
               		pid_file = fopen(pidfilename, "r");
               		if (pid_file)
               			{
                       		fclose(pid_file);
                       		pid=read_pid(pidfilename);
                       		}
             		if (pid > 0)
                		{
		       		sprintf(procfilename,"/proc/%d",pid);
	        		pid_file = fopen(procfilename, "r");
	       			if (pid_file)
               				{
	               			fclose(pid_file);
					}
				else
       	        			{
					remove_pid(pidfilename);
					pid=0;
					}
				}
       	        	if (pid > 0)
       	        		{
				fprintf(stdout, "[DCP] STARTED CI%d %d\n",slot, pid);
				}
			else
       	        		{
				fprintf(stdout, "[DCP] STARTING CI%d\n", slot);
				ret=dreamciplus(ci_command, slot);
				}
      			}
		else
			{
			fprintf(stdout, "[DCP] DISABLED CI%d\n", slot);
       	     		}
		}
	else
		{
		fprintf(stdout, "[DCP] MISSING CI%d\n", slot);
       	     	}
	return ret;
	}

int stop(int slot)
	{
	int ret=0;
	int pid=0;
        FILE *pid_file;
        char pidfilename[32];
	ci_command=STOP;
    	sprintf(pidfilename,"/var/run/ca/dreamciplus%d.pid",slot);
     	pid_file = fopen(pidfilename, "r");
	if (pid_file > 0)
	    {
	    fclose(pid_file);
	    while (pid == 0)
		{
		pid=read_pid(pidfilename);
		if (pid > 0)
			{
			fprintf(stdout, "[DCP] STOPPING CI%d %d\n",slot, pid);
			kill(pid, SIGABRT);
			sleep(1);
			}
		}
	    ret=1;
	    }
	fprintf(stdout, "[DCP] STOPPED  CI%d %d\n",slot, pid);
	return ret;
	}

int restart(int slot)
	{
	int ret;
	ret=stop(slot);
	sleep(3);
	ret=start(slot);
	return ret;
	}

int setInit(int slot)
	{
	int ret;
	fprintf(stdout, "[DCP] INIT  CI%d\n",slot);
	ret=stop(slot);
        sleep(3);	
	ret=start(slot);
	return ret;
	}

int setReset(int slot)
	{
	int ret;
	fprintf(stdout, "[DCP] RESET CI%d\n",slot);
	reset_auth(slot);
	ret=stop(slot);
	ret=start(slot);
	return ret;
	}

int setErase(int slot)
	{
	fprintf(stdout, "[DCP] ERASE CI%d\n",slot);
	reset_auth(slot);
	return 0;
	}

