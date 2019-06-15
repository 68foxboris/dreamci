STATIC = -static
# change for embedded certificates
DFLAG=EMBEDDED

LDLIBS = -Wl,--gc-sections,--strip-all,--discard-all -Os $(STATIC) -lcrypto -pthread
CFLAGS = -Wall -Os -fPIC $(STATIC) -D $(DFLAG) \
	-fdata-sections -ffunction-sections -fno-exceptions

bin_PROGRAMS = dreamciplus

default: dreamciplus 

res_standard = res_ca_support.o res_app_info.o res_mmi.o res_datetime.o
res_ciplus = res_content_ctrl.o res_cam_upgrade.o res_host_lac.o res_host_ctrl.o res_app_mmi.o res_fifo.o

misc = aes_xcbc_mac.o list.o misc.o dh_rsa_misc.o descrambler.o assign.o socket.o pid.o nohup.o journal.o

dreamciplus:	main.o dreamciplus.o $(res_standard) $(res_ciplus) $(misc)
		$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

shared:		$(res_standard) $(res_ciplus) $(misc)
		swig -python dreamciplus.i
		gcc -c -fPIC dreamciplus.c dreamciplus_wrap.c -lc -lcrypto \
        	-I/usr/include/python2.7 -lpython2.7
		gcc -shared *.o -o _dreamciplus.so -lc -lcrypto

clean:
		$(RM) dreamciplus *.o *.so *.py *wrap.c

systemd_unitdir = `pkg-config --print-errors --variable systemdsystemunitdir systemd`
systemd_unit_DATA = dreamciplus.service
