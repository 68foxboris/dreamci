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
extern int autopin;

int msgi=0;
char msg[1024];

static int handle_text(const uint8_t *data)
{
	int tag;
	int llen;
	int dlen;
	int i;

	tag = *data++ << 24;
	tag |= *data++ << 16;
	tag |= *data++;

	llen = parseLengthField(data, &dlen);
	if (msgi > 0)
		{
		data += llen;
		}

	for (i = 0; i <= dlen; i++)
            {
	    /* only standard ASCII text */
	    if ((data[i] >= 0x20) && (data[i] < 0x80))
	       {
	       /* save to long text message 
	          to make comparison easier */
	       msg[msgi]=data[i];
	       msgi++;
	       }
            }

	if (dlen > 1)
		{
	/* add space and make end 0 terminated */
	msg[msgi]=32;
	msgi++;
	msg[msgi]=0;
		}

	return 3 + llen + dlen;
}

static int ci_mmi_receive(struct ci_session *session, const uint8_t *tag, const uint8_t *data, unsigned int len)
{
        FILE *settings;
	char line[256];
	char cfg[256];
	char *ignore;
	int ll;
	int pin;
	int entered_pin=0;

	if (debug > 0) lprintf("mmi_receive()\n");
	if (debug > 4) lprintf(">>> %02x %02x %02x\n", tag[0], tag[1], tag[2]);
	if (debug > 4) hexdump(data, len);

	if ((tag[0] == 0x9f) && (tag[1] == 0x88)) {
		switch (tag[2]) {
		case 0x00:		// close 
			if (debug > 0) lprintf("CLOSE mmi\n");
			break;
		case 0x01: 		// display control
		{
			if (debug > 4) lprintf("DISPLAY control\n");
			uint8_t tag[3] = { 0x9f, 0x88, 0x02 };
			uint8_t data[2] = { 0x01, 0x01 };
			ci_session_sendAPDU(session, tag, data, 2);
			break;
		}
		case 0x07:              // pin query
		{
			if (debug > 4) lprintf("PIN query\n");
			const uint8_t *d = data;

			msgi=0;
			d += handle_text(d);
			msg[len-3]=0;

		        if (debug > 8) lprintf("%s\n", msg);
			if (strstr(msg,"Falscheingabe") || strstr(msg,"Bitte noch einmal") || strstr(msg,"Please try again") || strstr(msg,"Incorrect PIN"))
			      {
			      /* remove the PIN file */
    			      char pinfilename[32];
    			      sprintf(pinfilename,"/var/run/ca/dreamciplus%d.pin",session->slot_index);
    			      remove_pid(pinfilename);
			      }

			uint8_t tag[3] = {0x9f, 0x88, 0x08};
			/* default PIN 1234 - not used */
			uint8_t data[5] = {0x01, 0x31, 0x32, 0x33, 0x34};
			/* pin answer */
     			settings = fopen("/etc/enigma2/settings", "rb");
				if (settings) 
				   {
 				   while ( fgets ( line, sizeof(line), settings ) != NULL ) /* read a line */ {
   		             		sprintf(cfg,"config.ci.%d.pin=",session->slot_index);
                			if (strncmp(line,cfg,16) == 0) {
              	         		pin=atol(line+16);
					if (pin > 0) 
						{
		        	    	        fclose(settings);
			   			/* pin answer */
//	       					if (debug > 10) lprintf("CI%d PIN: %d\n",session->slot_index,pin);
			   			sprintf((char *)data+1,"%04d",pin);	
			   			if (debug > 0) lprintf("CI%d PIN ENTERED from Classic settings\n",session->slot_index);
			   			ci_session_sendAPDU(session, tag, data, 5);
						return 0;
                	       			}
                        		}
   		             		sprintf(cfg,"config.ci.%d.static_pin=",session->slot_index);
                			if (strncmp(line,cfg,23) == 0) {
              	         		pin=atol(line+23);
					if (pin > 0) 
						{
		        	    	        fclose(settings);
			   			/* pin answer */
//	       					if (debug > 10) lprintf("CI%d PIN: %d\n",session->slot_index,pin);
			   			sprintf((char *)data+1,"%04d",pin);	
			   			if (debug > 0) lprintf("CI%d PIN ENTERED from Open settings\n",session->slot_index);
			   			ci_session_sendAPDU(session, tag, data, 5);
						return 0;
                	       			}
                        		}
                		   }
        	    	       fclose(settings);
                	       }
			/* get autopin */
	        	char pinfilename[32];
                	sprintf(pinfilename,"/var/run/ca/dreamciplus%d.pin",session->slot_index);
			entered_pin=read_pid(pinfilename);
			if (entered_pin > 9999 || entered_pin < 0) entered_pin=0;
			if (autopin && entered_pin > 0)
				{
				sprintf((char *)data+1,"%04d",entered_pin);
	   			if (debug > 0) lprintf("CI%d AUTO PIN ENTERED\n",session->slot_index);
	   			ci_session_sendAPDU(session, tag, data, 5);
				return 0;
				}
					
			break;
		}
		case 0x09:              // t_menu_last
		{
			if (debug > 4) lprintf("MENU last\n");
			const uint8_t *d = data;
			int choice_nb = *d++;
			int i;
	   		uint8_t tag[3] = { 0x9f, 0x88, 0x08 };
			uint8_t data[2] = { 0x01, 0x01 };

			msgi=0;
			d += handle_text(d);
			d += handle_text(d);
			d += handle_text(d);
			for (i = 0; i < choice_nb; i++)
				d += handle_text(d);

		        if (debug > 8) lprintf("%s\n", msg);
			if (strstr(msg,"Minuten gesperrt") || strstr(msg,"Minuten  gesperrt") || strstr(msg,"blocked for"))
			      {
			      /* remove the PIN file */
    			      char pinfilename[32];
    			      sprintf(pinfilename,"/var/run/ca/dreamciplus%d.pin",session->slot_index);
    			      remove_pid(pinfilename);
		    	      return 0;
			      }

     			settings = fopen("/etc/enigma2/settings", "rb");
			if (settings)
			   {
 			   while ( fgets ( line, sizeof(line), settings ) != NULL ) 
				{
                		sprintf(cfg,"config.ci.%d.confirm=",session->slot_index);
//                		printf("CI setting: %s\n",cfg);
                		if (strncmp(line,cfg,20) == 0)
					{
                        		ignore=line+21;
					ll=strlen(ignore);
					ignore[ll-2]=0;
//                           		printf( "!%s!\n", ignore); 
					char ck[32];
					const char k[2] = ",";
        				char *token;
   					/* get the first token */               
                        		token = strtok(ignore, k);                
                        		/* walk through other tokens */         
                        		while( token != NULL )                  
                                		{                               
                                                /* ommit blank at beginning */
                                                if (token[0]==32) token++;
//	                             	 	printf( "!%s!\n", token); 
						sprintf(ck," %s ",token);
//	                             	 	printf( "!%s!\n", msg); 
						if (strcmp(token,"2")   == 0) strcpy(ck,"(2)");
						if (strcmp(token,"44")  == 0) strcpy(ck,"E04-4");
						if (strcmp(token,"74")  == 0) strcpy(ck,"I07-4");
						if (strcmp(token,"164") == 0) strcpy(ck,"E16-4");
						if (strcmp(token,"304") == 0) strcpy(ck,"E30-4");
						if (strcmp(token,"349") == 0) strcpy(ck,"I34-9");
						if (strcmp(token,"101") == 0) strcpy(ck,"D101");
						if (strcmp(token,"103") == 0) strcpy(ck," 103)");
						if (strcmp(token,"204") == 0) strcpy(ck," 204)");
						if (strcmp(token,"992") == 0) strcpy(ck,"Alterseinstufung");
						if (strcmp(token,"8193") == 0) strcpy(ck,"8193");
						if (strstr((const char *)msg, ck))
							{
			        	    	        fclose(settings);
//							printf("IGNORE: %s\n",msg);
							if (debug > 0) lprintf("\n");
							if (debug > 0) lprintf("AUTO CONFIRMED: %s message\n",token);
							ci_session_sendAPDU(session, tag, data, 2);
							return 0;
							}
                                		token = strtok(NULL, k);                        
                				}
               				}
                		}
        	    	       fclose(settings);
			   }
                	break;
        	}
		case 0x0c:              // t_list_last
		{
			if (debug > 4) lprintf("LIST last\n");
			const uint8_t *d = data;
			int choice_nb = *d++;
			int i;
			uint8_t tag[4] = { 0x9f, 0x88, 0x0b, 0x01 };
			uint8_t tag2[4] = { 0x9f, 0x88, 0x00, 0x00 };
			uint8_t data[1] = { 0x00 };

			msgi=0;
			d += handle_text(d);
			d += handle_text(d);
			d += handle_text(d);
			for (i = 0; i < choice_nb; i++)
				d += handle_text(d);

		        if (debug > 8) lprintf("%s\n", msg);
			if (strstr(msg,"neben den Senderlogos") || strstr(msg,"next to the channel"))
				{
				if (debug > 0) lprintf("AUTO CONFIRMED: %s message\n",msg);
				ci_session_sendAPDU(session, tag, data, 1);
				ci_session_sendAPDU(session, tag2, data, 0);
		    		return 0;
				}

     			settings = fopen("/etc/enigma2/settings", "rb");
			if (settings)
			   {
 			   while ( fgets ( line, sizeof(line), settings ) != NULL )
				{
                		sprintf(cfg,"config.ci.%d.confirm=",session->slot_index);
//                		printf("CI setting: %s\n",cfg);
                		if (strncmp(line,cfg,20) == 0)
					{
                        		ignore=line+21;
					ll=strlen(ignore);
					ignore[ll-2]=0;
//                           		printf( "!%s!\n", ignore); 
					const char k[2] = ",";
					char ck[32];
        				char *token;
                        		token = strtok(ignore, k);                
                        		while( token != NULL )                  
                                		{                               
                                                /* ommit blank at beginning */
                                                if (token[0]==32) token++;
//	                             	 	printf( "!%s!\n", token); 
						sprintf(ck," %s ",token);
						if (strcmp(token,"990") == 0) strcpy(ck," to subscribe to ");
						if (strcmp(token,"991") == 0) strcpy(ck," zu abonnieren.");
						if (strcmp(token,"992") == 0) strcpy(ck,"Alterseinstufung");
						if (strcmp(token,"993") == 0) strcpy(ck," not inserted");
						if (strcmp(token,"101") == 0) strcpy(ck,"D101");
						if (strcmp(token,"103") == 0) strcpy(ck," 103)");
						if (strcmp(token,"204") == 0) strcpy(ck," 204)");
						if (strcmp(token,"536") == 0) strcpy(ck," 536");
						if (strcmp(token,"8193") == 0) strcpy(ck,"8193");
//	                             	 	printf( "!%s!\n", msg); 
						if (strstr((const char *)msg, ck))
							{
			        	    	        fclose(settings);
//							printf("IGNORE: %s\n",msg);
							if (debug > 0) lprintf("\n");
							if (debug > 0) lprintf("AUTO CONFIRMED: %s message\n",token);
							ci_session_sendAPDU(session, tag, data, 1);
							ci_session_sendAPDU(session, tag2, data, 0);
							return 0;
							}
                                		token = strtok(NULL, k);                        
                				}
               				}
                		}
        	    	       fclose(settings);
			   }  
			break;
        	}
		default:
			if (debug > 9) lprintf("unknown apdu tag %02x\n", tag[2]);
		}
	}

	return 0;
}

static void ci_mmi_doAction(struct ci_session *session)
{
	if (debug > 9) lprintf("mmi_doAction()\n");

	switch (session->state) {
	case started:
	{
		session->state = Final;
		session->action = 0;
		break;
	}
	default:
		if (debug > 0 ) lprintf("unknown mmi state\n");
	}
}

const struct ci_resource resource_mmi = {
	.id = 0x400041,
	.receive = ci_mmi_receive,
	.doAction = ci_mmi_doAction,
};
