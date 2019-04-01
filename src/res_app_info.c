#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#include "session.h"
#include "resource.h"
#include "misc.h"

extern int debug;
extern int ci_number;

static int ci_appmgr_receive(struct ci_session *session, const uint8_t *tag, const uint8_t *data, unsigned int len)
{
	if (debug > 3) lprintf("appmgr_receive()\n");
//	if (debug > 4) hexdump(tag, 3);

	unsigned int app_type, app_manufacturer, manufacturer_code;
	const uint8_t *data_am;
	data_am=data;

	if (len)
		{
		if (debug >4) hexdump(data, len);
		}
	else
		{
		if (debug >4) hexdump(data, len);
		}

	if ((tag[0] == 0x9f) && (tag[1] == 0x80)) {
		switch (tag[2]) {
		case 0x21:
		{
			if (debug > 3) lprintf("application info\n");
			app_type = *data_am++;
			app_manufacturer = *data_am++ << 8;
			app_manufacturer|= *data_am++;
			manufacturer_code = *data_am++ << 8;
			manufacturer_code|= *data_am++;
			if (debug > 9) lprintf("TYPE:         %d\n", app_type);
			if (debug > 9) lprintf("MANUFACTURER: %d\n", app_manufacturer);
			if (debug > 9) lprintf("CODE:         %d\n", manufacturer_code);
			ci_session_set_app_name(session, &data[6], data[5]);
			break;
		}
		case 0x23:
		{
			if (debug > 3) lprintf("cicam reset\n");
			app_type = *data_am++;
			app_manufacturer = *data_am++ << 8;
			app_manufacturer|= *data_am++;
			manufacturer_code = *data_am++ << 8;
			manufacturer_code|= *data_am++;
			if (debug > 9) lprintf("TYPE:         %d\n", app_type);
			if (debug > 9) lprintf("MANUFACTURER: %d\n", app_manufacturer);
			if (debug > 9) lprintf("CODE:         %d\n", manufacturer_code);
			ci_session_set_app_name(session, &data[6], data[5]);
			break;
		}
		default:
			if (debug > 0) lprintf("unknown appmgr apdu tag %02x\n", tag[2]);
		}
	}

	return 0;
}

static void ci_appmgr_doAction(struct ci_session *session)
{
	if (debug > 0) lprintf("appmgr_doAction()\n");

	switch (session->state) {
	case started:
	{
		uint8_t tag[3] = { 0x9f, 0x80, 0x20 };
		ci_session_sendAPDU(session, tag, 0, 0);
		session->state = Final;
		session->action = 0;
		break;
	}
	default:
		if (debug > 0) lprintf("unknown appmgr state\n");
	}
}

const struct ci_resource resource_app_info3 = {
	.id = 0x20043,
	.receive = ci_appmgr_receive,
	.doAction = ci_appmgr_doAction,
};

const struct ci_resource resource_app_info2 = {
	.id = 0x20042,
	.receive = ci_appmgr_receive,
	.doAction = ci_appmgr_doAction,
};

const struct ci_resource resource_app_info1 = {
	.id = 0x20041, 
	.receive = ci_appmgr_receive,
	.doAction = ci_appmgr_doAction,
};
