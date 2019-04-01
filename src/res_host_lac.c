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
extern int can_high_bitrate;
extern int ci_number;

static int ci_host_lac_receive(struct ci_session *session, const uint8_t *tag, const uint8_t *data, unsigned int len)
{
        FILE *settings;
        char line[256];
        char *cfgd="config.osd.language=de_DE";
        char *cfgf="config.osd.language=fr_FR";

	if (debug > 0) lprintf("host_lac_receive()\n");
	hexdump(tag, 3);
	if (len)
		hexdump(data, len);

        uint8_t data_reply[4]; 
 	data_reply[0] = 0x65; /* e */
 	data_reply[1] = 0x6e; /* n */
 	data_reply[2] = 0x67; /* g */
 	data_reply[3] = 0; 

	/* check for German or French in enigma2 settings, 
           if not found use English */
        settings = fopen("/etc/enigma2/settings", "rb");
        if (settings)
              {
              /* read a line */
              while ( fgets ( line, sizeof(line), settings ) != NULL )
                {
                if (strncmp(line,cfgd,25) == 0)
                   {
#ifdef ENGLISH
 		   data_reply[0] = 0x67; /* g */
 	           data_reply[1] = 0x65; /* e */
		   data_reply[2] = 0x72; /* r */
#else
 	           data_reply[0] = 0x64; /* d */
 	           data_reply[1] = 0x65; /* e */
	           data_reply[2] = 0x75; /* u */
#endif
                   }
                if (strncmp(line,cfgf,25) == 0)
                   {
#ifdef ENGLISH
 		   data_reply[0] = 0x66; /* f */
 	           data_reply[1] = 0x72; /* r */
		   data_reply[2] = 0x65; /* e */
#else
 	           data_reply[0] = 0x66; /* f */
 	           data_reply[1] = 0x72; /* r */
	           data_reply[2] = 0x61; /* a */
#endif
                   }
                 }
              fclose(settings);
              }

	if ((tag[0] == 0x9f) && (tag[1] == 0x81)) {
		switch (tag[2]) {
		case 0x00: /* country enquiry */
		{
			if (debug > 4) lprintf("country answered with '%s'\n", data_reply);
			uint8_t tag[3] = { 0x9f, 0x81, 0x01 }; /* host country reply */
			ci_session_sendAPDU(session, tag, data_reply, 3);
			break;
		}
		case 0x10: /* language enquiry */
		{
			if (debug > 4) lprintf("language answered with '%s'\n", data_reply);
			uint8_t tag[3] = { 0x9f, 0x81, 0x11 }; /* host language reply */
			ci_session_sendAPDU(session, tag, data_reply, 3);
			break;
		}
		default:
			if (debug > 0) lprintf("unknown host lac apdu tag %02x\n", tag[2]);
		}
	}

	return 0;
}

static void ci_host_lac_doAction(struct ci_session *session)
{
	if (debug > 0) lprintf("host_lac_doAction()\n");

	switch (session->state) {
	case started:
	{
		uint8_t tag[3] = {0x9f, 0x80, 0x20};
		ci_session_sendAPDU(session, tag, 0, 0);
		session->state = Final;
		session->action = 0;
		break;
	}
	default:
		if (debug > 0) lprintf("unknown host lac state\n");
	}

	session->action = 0;
}

const struct ci_resource resource_host_lac = {
	.id = 0x8d1001,
	.receive = ci_host_lac_receive,
	.doAction = ci_host_lac_doAction,
};
