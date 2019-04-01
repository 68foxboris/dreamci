#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "session.h"
#include "resource.h"
#include "socket.h"
#include "descrambler.h"

#include "misc.h"

int unicable=0;
extern char old_buf_tuner[8];
extern char old_buf_device[32];
extern char old_buf_module[8];
extern char fullserviceref[64];
extern char oldpids[256];

extern int ci_number;
extern int justplay;
extern int current;
extern int assigned;
extern int descrambles;
extern char demux_device[25];

#define MAX_PID_REMOVE 8192

int timer_first_request=0; 

#define MAX_CAIDS 16

#define DMX_START       _IO('o', 41)
#define DMX_STOP        _IO('o', 42)

extern int debug;

struct camgr_data {
	uint32_t caids[MAX_CAIDS];
	int first_service;
};

static void camgr_caids_clear(struct camgr_data *d)
{
	int i;
	if (debug > 0) lprintf("CI%d CLEARING CAIDs\n", ci_number);

	for (i = 0; i < MAX_CAIDS; i++)
		d->caids[i] = 0;
}

static int camgr_caids_add(struct camgr_data *d, unsigned int caid)
{
	int i;

	for (i = 0; i < MAX_CAIDS; i++)
		if (!d->caids[i]) {
			d->caids[i] = caid;
			return 0;
		}
	return -1;
}

static int camgr_caid_valid(struct camgr_data *d, unsigned int caid)
{
	int i;

	for (i = 0; i < MAX_CAIDS; i++) {
		if (!d->caids[i])
			break;
		if (d->caids[i] == caid)
			{
//			if (debug > 8) lprintf("CAID:  %x\n",caid);
			return 1;
			}
	}
	return 0;
}

static int camgr_caid_count(struct camgr_data *d)
{
	int i;

	for (i = 0; i < MAX_CAIDS; i++)
		if (!d->caids[i])
			break;
	return i;
}

static struct camgr_data *camgr_data_check_init(struct ci_session *s)
{
	struct camgr_data *data;

	if (s->private_data)
		return s->private_data;

	data = malloc(sizeof(struct camgr_data));
	if (!data) {
		if (debug > 0) lprintf("out of memory\n");
		return NULL;
	}

	memset(data, 0, sizeof(struct camgr_data));
	data->first_service = 1;

	s->private_data = data;

	return s->private_data;
}

static void camgr_set_demux_data(struct ci_session *session, int demux_idx, const uint8_t *tuner, size_t tuner_len, int enable_ci)
{
	struct camgr_data *d = session->private_data;
	const char demux_dest[] = "/proc/stb/tsmux/input%d";
	const char demux_dev[] = "/dev/dvb/adapter0/demux%d";
	const char used_ci[] = "/proc/stb/tsmux/ci%d_input";
	const char buf_devname_new[][4] = { "CI0", "CI1" }; 
	const char *buf_devname[2];
	char buf_tuner[8];
	char buf_device[64];
	FILE *f;

	buf_devname[0] = buf_devname_new[0];
	buf_devname[1] = buf_devname_new[1];

	if (tuner_len >= sizeof(buf_tuner)) {
		if (debug > 0) lprintf("malformed tuner descriptor\n");
		return;
	}
	memcpy(buf_tuner, tuner, tuner_len);
	buf_tuner[tuner_len] = 0;

	int standby=0;
	standby=check_standby();

	int timer=0;
	timer=check_timer(fullserviceref, 1);
	if ((timer == 1) && (timer_first_request == 0))
	   {
           timer_first_request=1;
	   }
	else
	   {
           timer_first_request=0;
	   }
	if (debug > 9) lprintf("TIMER %d first %d standby %d justplay %d same %d\n", timer,timer_first_request,standby,justplay,current);

	/* check for setting to disable recording first timer write
           unicable fix */
        FILE *settings;
        char line[256];
	line[255]=0; /* avoids crashes */
        char *cfg1="configMode=advanced";
        char *cfg2="unicableLnb";
        char *cfg3="advanced.sat";
        char *cfg4="unicableconnected";
        char *cfg5="lof=unicable";
	settings = fopen("/etc/enigma2/settings", "rb");
	if (settings) 
	   {
 	   while ( fgets ( line, sizeof(line), settings ) != NULL ) 
		{
                /* only when lnb setting is advanced */
                if (strstr(line,cfg1) !=0)
                        { /* read next line */
 	   		if(!fgets ( line, sizeof(line), settings ))
                               {
                               if (debug > 0) lprintf("read error: %s\n", strerror(errno));
                               }

                	while ((strstr(line,cfg2) !=0) || (strstr(line,cfg3) !=0) || (strstr(line,cfg4) !=0))
				{ /* read further advanced lines */
 	   			if (!fgets ( line, sizeof(line), settings ))
                               		{
                               		if (debug > 0) lprintf("read error: %s\n", strerror(errno));
                               		}
				}
                	if (strstr(line,cfg5) !=0) 
				{ /* only if lof=unicable */
				unicable=1;
		        	}
		        }
		}
       	   fclose(settings);
       	   }
	if (unicable)
		{
		if (debug > 8) lprintf("CI%d UNICABLE found\n", ci_number);
		}
	else
		{
		if (debug > 8) lprintf("CI%d UNICABLE NOT found\n", ci_number);
		}

	snprintf(buf_device, sizeof(buf_device), used_ci, session->slot_index);
	/* recording timer fix ? */
	if (timer_first_request && !standby && !justplay && !unicable && !current)
		{
		if (debug > 8) lprintf("IGNORED %s <- %s\n", buf_device, buf_tuner);
		return;
		}

	if (enable_ci || d->first_service) {
		if (debug > 8) lprintf("INPUT %s <- %s\n", buf_device, buf_tuner);
		d->first_service = 0;
		f = fopen(buf_device, "r+");
		fwrite(buf_tuner, strlen(buf_tuner), 1, f);
		fclose(f);
	}
	
	snprintf(buf_device, sizeof(buf_device), demux_dest, demux_idx);
	/* remember also demux device */
	snprintf(demux_device, sizeof(demux_device), demux_dev, demux_idx);

	f = fopen(buf_device, "r+");
	if (enable_ci)
		{
		if (debug > 8) lprintf("ENABLED %s <- %s\n", buf_device, buf_devname[session->slot_index & 1]);
		fwrite(buf_devname[session->slot_index & 1], strlen(buf_devname[session->slot_index & 1]), 1, f);
		}
	else
		{
		if (debug > 8) lprintf("DISABLED %s <- %s\n", buf_device, buf_tuner);
		fwrite(buf_tuner, strlen(buf_tuner), 1, f);
		}
	fclose(f);
        sprintf(old_buf_device,"%s",buf_device); 
        sprintf(old_buf_tuner,"%s",buf_tuner);    
        sprintf(old_buf_module,"%s",buf_devname[session->slot_index & 1]);    
}

int add_caid_if_not_exist(int *caids, int max_caids, int caid)
{
	int i = 0;
	while (i < max_caids && caids[i] && caids[i] != caid)
		++i;
	if (i < max_caids && caids[i] == 0) {
		caids[i] = caid;
		return 1;
	}
	return 0;
}

int ci_camgr_capmt(struct ci_session *session, const unsigned char *data, unsigned int len)
{
	const uint8_t tag_ca_pmt[3] = { 0x9f, 0x80, 0x32 };
	unsigned int prg_info_len, dlen;
	unsigned int es_info_len, es_pid=0;
	uint8_t buf[2048];
	unsigned int pos;
	unsigned int i;
	struct camgr_data *d;
	int ca_available = 0;
	const uint8_t *demux_data = NULL;
	char newpid[8];
        int capmt_list=0;
        short capmt_serviceid=0;
        short capmt_version=0;
	if (debug > 5) lprintf("CI%d ASSIGNED: %d\n", ci_number,assigned);

 	/*
 	data[0] is capmt list management ... 
        on the first capmt for a service this is set to 0x03 ... 
        on update (new pmt) it is set to 0x05
 	this is easy usable to detect if this is a capmt 
	for a new service or if it is just a update
 
 	(data[1] << 8) | data[2] is the service id
 
 	((data[3] >> 1) & 0x1F) is the capmt version ... 
	it is changed on every update  0..15
 	*/

	d = camgr_data_check_init(session);

	capmt_list=data[0];
	capmt_serviceid=(data[1] << 8) | data[2];
	capmt_version=(data[3] >> 1) & 0x1F;
	prg_info_len = ((data[4] << 8) | data[5]) & 0xfff;
	if (debug > 9) lprintf("CAPMT list mgmt %02x serviceid %d version %d prog_info_len %d\n", capmt_list, capmt_serviceid, capmt_version, prg_info_len);
	if (debug > 8) hexdump(data, len);

	memcpy(buf, data, 7);
	pos = 7;

	int num_caids = 0;
	int caids[16] = {0};
	char caid_list[64] = {0};

	/* loop through prg_info */
	if (prg_info_len) {
		for (i = 7; i < (prg_info_len + 6); i += (dlen + 2)) {
			dlen = data[i + 1];
			if (data[i] == 0x09) { /* CA_DESCRIPTOR */
				uint32_t caid = ((data[i + 2] << 8) | data[i + 3]);
				if (camgr_caid_valid(d, caid)) {
					memcpy(buf + pos, data + i, dlen + 2);
					pos += dlen + 2;
					num_caids += add_caid_if_not_exist(caids, sizeof(caids)/sizeof(int), caid);
					ca_available = 1;
				}
			}
			if (data[i] == 0x85) /* e2 informs about src-tuner 
						and destination demux */
				{
				if (data[i + 1] <= 1)   /* there is no ts-destination - so skip entire capmt */
					{
					if (debug > 9) lprintf("CAIDs: %s but NO ts destination\n", caid_list);
					return 0;
					}
				demux_data = &data[i];
				}
		}
	}

 	/* set new prg_info_len */
 	buf[4] = ((pos - 6) >> 8);
 	buf[5] = (pos - 6);
 	char pid_out[256] = { 0 };
 
 	int pp = 0;
 	for (i = (prg_info_len + 6); i < len; i += es_info_len + 5) {
 		int copied = 0;
 		int cp_start = pos;
 		es_pid = ((data[i + 1] << 8) | data[i + 2]) & 0x1fff;
 		es_info_len = ((data[i + 3] << 8) | data[i + 4]) & 0xfff;
 		if (es_info_len > 0) { 
			/* check if we have ca descriptors at ES level
			  ... (for this single PID) */
 			int idx = i + 5;
 			int es_info_length = es_info_len;
 			++idx;	// skip capmt cmd id
 			--es_info_length;
 			while (es_info_length > 2) {
 				int l = 2 + data[idx + 1];
 				if (es_info_length < l)
					break;
 				if (data[idx] == 0x09) { /* CA_DESCRIPTOR */
 					uint32_t caid =
 					    ((data[idx + 2] << 8) |
 					     data[idx + 3]);
 					if (camgr_caid_valid(d, caid)) {
 						num_caids += add_caid_if_not_exist(caids, sizeof(caids)/sizeof(int), caid);
 						if (!copied) {
 							/* copy stream header up to descriptor start */
 							memcpy(buf + pos, data + i, 6);
 							copied += 6;
 							pos += 6;
 						}
 						memcpy(buf + pos, data + idx, l); // copy ca descriptor
 						copied += l;
 						pos += l;
 					}
 					else {
 						if (debug > 9)
 							lprintf("caid %04x not supported by CI\n", caid);
 					}
 				}
 				es_info_length -= l;
 				idx += l;
 			};

 			/* copy this pid when it is listed in prog info 
			   ... but skip ca descriptors at es level */
			if (!copied && ca_available) {
				/* copy stream type, es pid, es info len */
				memcpy(buf + pos, data + i, 5);
				copied += 5;
				pos += 5;
			}

 			if (es_info_length != 0 && debug > 9) {
 				lprintf("es_info broken at capmt idx %d, PID %04x, es_info_len %d, es_info_length %d",
 						idx, es_pid, es_info_len, es_info_length);
 				pos -= copied; /* do not copy PIDs with broken es_info */
 			}
 			else {
 				/* set new es_info_len */
 				buf[cp_start+3] = (copied-5) >> 8;
 				buf[cp_start+4] = (copied-5) & 0xFF;
 			}

 		}
 		else if (ca_available) { // no ca descriptors at es level... but at program level .. so this PID is interesting for the CI
			memcpy(buf + pos, data + i, es_info_len + 5);
			pos += es_info_len + 5;
			copied += es_info_len + 5;
 		}
 		if (copied) {
 			sprintf(newpid, " %04x", es_pid);
 			if (!strstr(oldpids, newpid)) { /* check if pid is not in oldpids... */
 				if (assigned) descrambler_set_pid(session->slot_index, 1,
 							es_pid);
 				if (debug > 9)
 					lprintf("PID + %04x\n", es_pid);
 			}
 			sprintf(pid_out, "%s %04x ", pid_out, es_pid);
 			pp++;
		}
 	}
 
 	int mm = 0; /* counter for removed PIDs */ 
 	/* now we disable all PIDs which are existing in oldpids list ... 
           but not in new pids */
	if (debug > 9)
		{
		if (strlen(oldpids) > 0) lprintf("OLD   PIDs: %s\n", oldpids);
		if (strlen(pid_out) > 0) lprintf("NEW   PIDs: %s\n", pid_out);
		}
 	char *token = strtok(oldpids, " ");
 	while (token != NULL) {
//		if (debug > 9) lprintf("checking PID: %s\n", token);
 		if (!strstr(pid_out, token)) {
 			unsigned int pid = (int)strtol(token, NULL, 16);
 			if (assigned) descrambler_set_pid(session->slot_index, 0, pid);
 			if (debug > 9)
				{
// 				lprintf("PID - %s\n", token);
 				lprintf("PID - %04x\n", pid);
				}
			mm++;
 		}
 		token = strtok(NULL, " ");
 	}

 	for (i = 0; i < num_caids; ++i) {
		if (strlen(caid_list) == 0) {
			sprintf(caid_list, "%x", caids[i]);
		} else {
			sprintf(caid_list,
					"%s %x",
					caid_list,
					caids[i]);
		}
 	}

	if (assigned && (strlen(caid_list)) > 0) {
		if (debug > 9) lprintf("CAIDs: %s\n", caid_list);
        	write_caid_file(caid_list);
		}
	else
		{
		if (check_caid_file()) 
			{
	        	remove_caid_file(caid_list);
			}
		}

 	if (demux_data) 
		{
		/* only if CI is assigned we ask for help */
		if (assigned) camgr_set_demux_data(session, demux_data[2], &demux_data[3], demux_data[1] - 1, num_caids);
		}

	if ((pp > 0) && (debug > 9)) lprintf("SENT  PID #%d:  %s\n", pp, pid_out);

	/* remember set pid for next reset */
	if (assigned) strcpy(oldpids,pid_out);
	
	if (debug > 8) hexdump(buf, pos);

	if ((buf[0] == 5) && (mm == 1)) /* when only 1 audio pid was removed */
		{
		if (debug > 9) lprintf("CAPMT list 5 surpressed\n");
		}
	else
		{
		/* only if CI is assigned we ask for help */
		if (assigned) ci_session_sendAPDU(session, tag_ca_pmt, buf, pos);
		}

	return 0;
}

static int ci_camgr_receive(struct ci_session *session, const uint8_t *tag, const uint8_t *data, unsigned int len)
{
	struct camgr_data *d;
	unsigned int i;

	d = camgr_data_check_init(session);

	if (debug > 0) lprintf("camgr_receive()\n");

	if ((tag[0] == 0x9f) && (tag[1] == 0x80)) {
		switch (tag[2]) {
		case 0x31:
			camgr_caids_clear(d);
			socket_uninstall_cb(session);

			for (i = 0; i < len; i += 2)
				camgr_caids_add(d, ((data[i] << 8) | (data[i + 1])));

			if (camgr_caid_count(d))
				socket_install_cb(session, ci_camgr_capmt);

			break;
		default:
			if (debug > 0) lprintf("unknown apdu tag %02x\n", tag[2]);
		}
	}

	return 0;
}

static void ci_camgr_doAction(struct ci_session *session)
{
	struct camgr_data *d;
	unsigned int i;

	d = camgr_data_check_init(session);
	if (debug > 10) {
		lprintf("CAIDs supported by CI:\n");
		i = 0;
		while (i < MAX_CAIDS && d->caids[i])
			lprintf("%04x\n", d->caids[i++]);
	}


	if (debug > 0) lprintf("camgr_doAction()\n");

	switch (session->state) {
	case started:
	{
		if (debug > 0) lprintf("reply started\n");
		uint8_t tag[3] = { 0x9f, 0x80, 0x30 };
		ci_session_sendAPDU(session, tag, 0, 0);
		session->state = Final;
		session->action = 0;
		break;
	}
	case Final:
		if (debug > 0) lprintf("state Final and action should not happen\n");
		break;
	default:
		if (debug > 0) lprintf("unknown camgr state\n");
	}

	session->action = 0;
}

const struct ci_resource resource_ca_support = {
	.id = 0x30041,
	.receive = ci_camgr_receive,
	.doAction = ci_camgr_doAction,
};
