#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/dvb/ca.h>
#include <sys/utsname.h>
#include <errno.h>
#include <sys/file.h>

extern void lprintf(char* message,...);
extern void return_ci(int sig);
extern char *dreambox;

extern int debug;
extern int resetting;
extern int ci_number;
extern int ca_device;
#define MAX_PID_REMOVE 8192 
#define SIGRESTART      99

int old_index;
int old_parity;
unsigned char *old_data;

enum ca_descr_data_type {
	CA_DATA_IV,
	CA_DATA_KEY,
};

enum ca_descr_parity {
	CA_PARITY_EVEN,
	CA_PARITY_ODD,
};

struct ca_descr_data {
	unsigned int index;
	enum ca_descr_parity parity;
	enum ca_descr_data_type data_type;
	unsigned int length;
	unsigned char *data;
};


struct ca_descr_s {
	unsigned int index;
	unsigned int parity;
	unsigned char cw[8];
};

#define CA_SET_DESCR_DATA_DREAM _IOW('o', 137, struct ca_descr_data)
#define CA_SET_DESCR_DATA _IOW('o', 10, struct ca_descr_data)

int desc_fd;

int descrambler_init(void)
{
	char filename[22];

	sprintf(filename, "/dev/dvb/adapter0/ca%d", ca_device);
	if (debug > 9) lprintf("CI%d CA device: %s\n", ci_number, filename);

	desc_fd = open(filename, O_RDWR | O_NONBLOCK );
	if (desc_fd <= 0) 
		{
		lprintf("can not open device %s (errno=%d %s)", filename, errno, strerror(errno));
		return 1;
		}

	return 0;
}

void descrambler_deinit(void)
{
	close(desc_fd);
	desc_fd=-1;
}

void descrambler_reset_ca(void)
{              
if (ioctl(desc_fd, CA_RESET, NULL))
	{
	if (debug > 0) lprintf("CA_RESET (errno=%d %s)\n", errno, strerror(errno));
	}
}

int descrambler_set_key(int index, int parity, unsigned char *data)
{
	struct ca_descr_data d;
	d.index = index;
	d.parity = parity;
	d.data_type = CA_DATA_KEY;
	d.length = 16;
	d.data = data;
	old_data=data;
	old_index=index;
	old_parity=parity;
	int ret;

        if (dreambox == NULL)                                                   
           {           
           if (debug > 0) lprintf("ALIEN ...\n");
	   ret=ioctl(desc_fd, CA_SET_DESCR_DATA, &d);
           }             
        else              
           {          
           if (debug > 0) lprintf("DREAMBOX %s ...\n", dreambox);
	   ret=ioctl(desc_fd, CA_SET_DESCR_DATA_DREAM, &d);
           }       
	if (ret)
		{
		if (debug > 0) lprintf("CA_SET_DESCR_DATA index=0x%04x parity=0x%04x (errno=%d %s)\n", index, parity, errno, strerror(errno));
		}
	else
		{
		if (debug > 0) lprintf("CA_SET_DESCR_DATA index=0x%04x parity=0x%04x\n", index, parity);
		}

	d.index = index;
	d.parity = parity;
	d.data_type = CA_DATA_IV;
	d.length = 16;
	d.data = data + 16;

        if (dreambox == NULL)                                                   
           {           
           if (debug > 0) lprintf("NO DREAM ...\n");
	   ret=ioctl(desc_fd, CA_SET_DESCR_DATA, &d);
           }             
        else              
           {          
           if (debug > 0) lprintf("DREAMBOX %s ...\n", dreambox);
	   ret=ioctl(desc_fd, CA_SET_DESCR_DATA_DREAM, &d);
           }       
	if (ret)
		{
		if (debug > 0) lprintf("CA_SET_DESCR_DATA index=0x%04x parity=0x%04x (errno=%d %s)\n", index, parity, errno, strerror(errno));
		}
	else
		{
		if (debug > 0) lprintf("CA_SET_DESCR_DATA index=0x%04x parity=0x%04x\n", index, parity);
		}
	return 0;
}

int descrambler_set_pid(int index, int enable, int pid)
{
	struct ca_pid p;          
        unsigned int flags = 0x80;

        p.pid = pid;              

        if (index)              
              	flags |= 0x40;         
                                
        if (enable)                        
               	flags |= 0x20;             

        p.index = flags;                   
                                 
	if (ioctl(desc_fd, CA_SET_PID, &p)==-1)
		{
		if (debug > 9) lprintf("CA_SET_PID pid=0x%04x index=0x%04x (errno=%d %s)\n", p.pid, p.index, errno, strerror(errno));
		}
	else
		{
		if (debug > 9) lprintf("CA_SET_PID pid=0x%04x index=0x%04x\n", p.pid, p.index);
		}

	return 0;
}

