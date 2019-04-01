#ifndef __MISC_H_
#define __MISC_H_

#define IS_CTRL  (1 << 0)
#define IS_EXT   (1 << 1)
#define IS_ALPHA (1 << 2)
#define IS_DIGIT (1 << 3) 

void init_strip_table();

void push_other();

void strip(char * str, int what);

void lprintf(char* message,...);

void reset_auth(int ci_number);

int nohup(char* command);

int notify();

void cert_strings(char* certifile);

int check_enigma2();

int check_journal();

int file_opened(char *filename, pid_t pid);

int write_input();

int write_proc();

int write_bitrate(int enable);

int write_caid_file(char *caids);

int remove_caid_file();

int check_caid_file();

int remove_ci();

int create_fifo();
int name_fifo();
int init_fifo_app();
int init_fifo_mmi();
int read_fifo();
int write_fifo();
int close_fifo();
int open_fifo();

time_t get_mtime(const char *path);

int check_timer(char *checkref, int verify);

int check_standby();

void hexdump(const uint8_t *data, unsigned int len);

void remove_service_file();

int write_pid (char *pidfile, int pid); 
int read_pid (char *pidfile); 
int remove_pid (char *pidfile);

int write_name_file (char *name); 
int remove_name_file (char *name);

int count_files(char *directory, char *starting);

int check_ci_assignment(const uint8_t *data, unsigned int len);

int parseLengthField(const unsigned char *pkt, int *len);

int get_random(unsigned char *dest, int len);

int add_padding(uint8_t *dest, unsigned int len, unsigned int blocklen);

void str2bin(uint8_t *dst, char *data, int len);

uint32_t UINT32(const uint8_t *in, unsigned int len);

int BYTE32(uint8_t *dest, uint32_t val);
int BYTE16(uint8_t *dest, uint16_t val);

#endif
