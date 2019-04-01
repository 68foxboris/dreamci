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

static int ci_app_mmi_receive(struct ci_session *session, const uint8_t *tag, const uint8_t *data, unsigned int len)
{
	if (debug > 0) lprintf("app_mmi_receive()\n");

	if ((tag[0] == 0x9f) && (tag[1] == 0x80)) 
		{
		switch (tag[2]) {
		case 0x21:
			if (debug > 0) lprintf("received tag %02x\n", tag[2]);
			break;
		default:
			if (debug > 0) lprintf("unknown apdu tag %02x\n", tag[2]);
		}
	}

	return 0;
}

static void ci_app_mmi_doAction(struct ci_session *session)
{
	if (debug > 0) lprintf("app_mmi_doAction()\n");

	switch (session->state) 
	{
	case started:
		{
		uint8_t tag[3] = { 0x9f, 0x80, 0x20 };
		ci_session_sendAPDU(session, tag, 0, 0);
		session->state = Final;
		session->action = 0;
		break;
		}
	default:
		if (debug > 0) lprintf("unknown state\n");
	}
}

const struct ci_resource resource_app_mmi1 = {
	.id = 0x410041,
	.receive = ci_app_mmi_receive,
	.doAction = ci_app_mmi_doAction,
};

const struct ci_resource resource_app_mmi2 = {
	.id = 0x410042,
	.receive = ci_app_mmi_receive,
	.doAction = ci_app_mmi_doAction,
};
