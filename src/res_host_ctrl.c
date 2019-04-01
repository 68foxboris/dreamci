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

static int ci_host_ctrl_receive(struct ci_session *session, const uint8_t *tag, const uint8_t *data, unsigned int len)
{
	if (debug > 0) lprintf("host_ctrl_receive()\n");

	if ((tag[0] == 0x9f) && (tag[1] == 0x84)) {
		switch (tag[2]) {
		case 0x00: /* tune          */
                        if (debug > 4) lprintf("should TUNE!\n");         
                        break;                         
		case 0x01: /* replace       */
                        if (debug > 4) lprintf("should REPLACE!\n");         
                        break;                         
		case 0x02: /* clear replace */
                        if (debug > 4) lprintf("should CLEAR!\n");         
                        break;                         
		case 0x03: /* ask release   */
                        if (debug > 4) lprintf("should RELEASE !\n");         
                        break;                         
		default:
			if (debug > 0) lprintf("unknown host ctrl apdu tag %02x\n", tag[2]);
		}
	}

	return 0;
}

static void ci_host_ctrl_doAction(struct ci_session *session)
{
	if (debug > 0) lprintf("host_ctrl_doAction()\n");

	switch (session->state) {
	/* may god bless you */
	case started:
	{
		uint8_t tag[3] = {0x9f, 0x80, 0x20}; /* appl info enq */
		ci_session_sendAPDU(session, tag, 0, 0);
		session->state = Final;
		session->action = 0;
		break;
	}
	default:
		if (debug > 0) lprintf("unknown state\n");
	}

	session->action = 0;
}

const struct ci_resource resource_host_ctrl1 = {
	.id = 0x200041,
	.receive = ci_host_ctrl_receive,
	.doAction = ci_host_ctrl_doAction,
};

const struct ci_resource resource_host_ctrl2 = {
	.id = 0x200042,
	.receive = ci_host_ctrl_receive,
	.doAction = ci_host_ctrl_doAction,
};
