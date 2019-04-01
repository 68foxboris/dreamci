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
extern int can_high_bitrate;

/* UNDER CONSTRUCTION - WEAR HELMET ! */

static int ci_multicr_receive(struct ci_session *session, const uint8_t *tag, const uint8_t *data, unsigned int len)
{
	if (debug > 3) lprintf("multicr_receive()\n");

	if (len > 4)
		{
		if (debug >4) hexdump(data, len);
		}

	if ((tag[0] == 0x9f) && (tag[1] == 0x92)) {
		switch (tag[2]) {
		case 0x01:
		      if (debug > 5) lprintf("multicr received pid_select request\n");
                      uint8_t tag2[3] = {0x9f, 0x92, 0x02};
		      /* send pid select reply */
                      ci_session_sendAPDU(session, tag2, 0, 0);
		      break;
		default:
			if (debug > 0) lprintf("unknown multicr apdu tag %02x\n", tag[2]);
		}
	}

	return 0;
}

static void ci_multicr_doAction(struct ci_session *session)
{
	if (debug > 0) lprintf("multicr_doAction()\n");

	switch (session->state) {
	case started:
	{
		uint8_t tag[3] = { 0x9f, 0x92, 0x00 };
		if (debug > 5) lprintf("multicr inits with apdu tag %02x\n", tag[2]);
		ci_session_sendAPDU(session, tag, 0, 0);
//		session->state = Final;
		session->action = 0;
		break;
	}
	default:
		if (debug > 0) lprintf("unknown multicr state\n");
	}
}

const struct ci_resource resource_multi_crypt = {
	.id = 0x900041,
	.receive = ci_multicr_receive,
	.doAction = ci_multicr_doAction,
};
