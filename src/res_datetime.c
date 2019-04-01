#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "session.h"
#include "resource.h"
#include "misc.h"

extern int debug;
extern int ci_number;
extern int bcd_time;

#define CONST1 15078.2 /* mjd for 1/3/1900? */                             
#define CONST2 365.25  /* average number of days in a year */              
#define CONST3 14956.1 /* ? */                                             
#define CONST4 30.6001 /* average number of days in a month */            
#define CONST5 14956   /* ? */        
 
long gregorian_to_mjd(int y, int m, int d)
	{
	int l;
	long int result;
	long mjd=0;

	if (m == 1 || m == 2)
		{
		l = 1;
		}
	else
		{
		l = 0;
		}

	result = CONST5 + d +
		(int)((y - l) * CONST2) +
		(int)((m + 1 + (l * 12)) * CONST4);

	mjd = (long int) result;
	return mjd;
	}

#define bcdtoint(i) ((((i & 0xf0) >> 4) * 10) + (i & 0x0f))

/* from dvb to check the MJDBCD value on debug */
void convert_date(char *dvb_buf)
{
  int i;
  int year, month, day, hour, min, sec;
  long int mjd;

  mjd = (dvb_buf[0] & 0xff) << 8;
  mjd += (dvb_buf[1] & 0xff);
  hour = bcdtoint(dvb_buf[2] & 0xff);
  min = bcdtoint(dvb_buf[3] & 0xff);
  sec = bcdtoint(dvb_buf[4] & 0xff);
/*
 * Use the routine specified in ETSI EN 300 468 V1.4.1,
 * "Specification for Service Information in Digital Video Broadcasting"
 * to convert from Modified Julian Date to Year, Month, Day.
 */
  year = (int)((mjd - CONST1)/CONST2);
  month = (int)((mjd - CONST3 - (int)(year * CONST2))/CONST4);
  day = mjd - CONST5 - (int)(year * CONST2) - (int)(month * CONST4);
  if (month == 14 || month == 15)
    i = 1;
  else
    i = 0;
  year += i;
  month = month - 1 - i * 12;
  lprintf("UTC MJDBCD: %04d:%02d:%02d %02d:%02d:%02d\n", year+1900,month,day,hour,min,sec);
}

static uint8_t byte_to_bcd(uint8_t value)
{
	uint8_t bcd;
	bcd = value % 10;
	value /= 10;
	bcd |= (value % 10) << 4;
	return bcd;
}

static int ci_datetime_receive(struct ci_session *session, const uint8_t *tag, const uint8_t *data, unsigned int len)
{
	if (debug > 0) lprintf("dtmgr_receive()\n");

	if ((tag[0] == 0x9f) && (tag[1] == 0x84)) {
		switch (tag[2]) {
		case 0x40:
			if (debug > 0) lprintf("req time\n");
			session->state = senddatetime;
			return 1;
			break;
		default:
			if (debug > 0) lprintf("unknown apdu tag %02x\n", tag[2]);
		}
	}

	return 0;
}

static void ci_datetime_doAction(struct ci_session *session)
{
	int msg_len=7;

	if (debug > 0) lprintf("dtmgr_doAction()\n");

	switch (session->state) {
	case started:
		if (debug > 0) lprintf("datetime started\n");
		break;
	case senddatetime:
		{
		if (debug > 0) lprintf("datetime answering\n");
		unsigned char tag[3] = { 0x9f, 0x84, 0x41 };     // date_time_response
		unsigned char msg[7] = { 0, 0, 0, 0, 0, 0, 0 };
		if (bcd_time)
			{
			struct timeval tv;
			struct tm* tod;
			gettimeofday (&tv, NULL);
//			tod = localtime (&tv.tv_sec);
			tod = gmtime (&tv.tv_sec);
			long mjd;
			/* Format date and time in BCD */
			msg[6] = 0;
			msg[5] = 0;
			msg[4] = byte_to_bcd(tod->tm_sec);
			msg[3] = byte_to_bcd(tod->tm_min);
			msg[2] = byte_to_bcd(tod->tm_hour);
			mjd=gregorian_to_mjd(tod->tm_year,tod->tm_mon+1,tod->tm_mday);
			uint hb, lb; /* high and low bytes from MJD */
			hb=mjd/256;
			lb=mjd-(hb*256);
//			if (debug > 9) lprintf("mjd: %d high byte: %d low byte: %d\n", mjd, hb, lb);
			msg[0]=hb;
			msg[1]=lb;
//			msg_len=5;
			if (debug > 9) convert_date((char *)msg);
			}
		ci_session_sendAPDU(session, tag, msg, msg_len);

		break;
		}
	default:
		if (debug > 0) lprintf("unknown date time state %d\n", session->state);
	}
	session->action = 0;
}

const struct ci_resource resource_datetime = {
	.id = 0x240041,
	.receive = ci_datetime_receive,
	.doAction = ci_datetime_doAction,
};
