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

static int ci_cam_upgrade_receive(struct ci_session *session, const uint8_t *tag, const uint8_t *data, unsigned int len)
{
	if (debug > 0) lprintf("cam_upgrade_receive()\n");

	if ((tag[0] == 0x9f) && (tag[1] == 0x9d)) {
		switch (tag[2]) {
		case 0x01:
			{
			if (debug > 4) lprintf("UPGRADE REQUEST starts\n");
        		uint8_t tag[3] = { 0x9f, 0x9d, 0x02 }; /* cam upgrade reply */
                        ci_session_sendAPDU(session, tag, 0, 0);
			break;
			}
		case 0x03:
			{
			if (debug > 4) lprintf("UPGRADE REQUEST continues\n");
        		uint8_t tag[3] = { 0x9f, 0x9d, 0x02 }; /* cam upgrade reply */
                        ci_session_sendAPDU(session, tag, 0, 0);
			break;
			}
		case 0x04:
			{
			if (debug > 4) lprintf("UPGRADE REQUEST completed\n");
        		uint8_t tag[3] = { 0x9f, 0x9d, 0x02 }; /* cam upgrade reply */
                        ci_session_sendAPDU(session, tag, 0, 0);
			break;
			}
		default:
			if (debug > 0) lprintf("unknown cam upgrade apdu tag %02x\n", tag[2]);
		}
	}

	return 0;
}

static void ci_cam_upgrade_doAction(struct ci_session *session)
{
	if (debug > 0) lprintf("cam_upgrade_doAction()\n");

	switch (session->state) {
	case started: /* not set ? */
	{
		uint8_t tag[3] = {0x9f, 0x80, 0x20};
		if (debug > 4) lprintf("send upgrade final\n");
		ci_session_sendAPDU(session, tag, 0, 0);
		session->state = Final;
		session->action = 0;
		break;
	}
	default:
		if (debug > 0) lprintf("unknown cam upgrade state\n");
	}
}

const struct ci_resource resource_cam_upgrade = {
	.id = 0x8e1001,
	.receive = ci_cam_upgrade_receive,
	.doAction = ci_cam_upgrade_doAction,
};
