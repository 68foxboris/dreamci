#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#include "session.h"
#include "resource.h"
#include "descrambler.h"
#include "aes_xcbc_mac.h"
#include "misc.h"
#include "dh_rsa_misc.h"
#include "_dh_params.h"

#ifdef EMBEDDED
#include "certs.h"
#include <shadow.h>
#endif

extern char ci_name[128];
extern char ci_name_underscore[128];

extern int ci_number;
extern int debug;
extern int extract_ci_cert;
extern int uri_version;

extern int quiet;
extern char authie[7];
extern char devie[7];

#ifndef FILENAME_MAX
#define FILENAME_MAX 256
#endif

#define MAX_PAIRS 5

/* storage & load of authenticated data (HostID & DHSK & AKH) */

static void get_authdata_filename(char *dest, size_t len, unsigned int slot)
   {
   int ret;
   FILE *auth_bin;
   char cin[128];
   char source[256];
   sprintf(source, "ci_auth_slot_%d.bin", slot);
   char target[256];
   char sourcepath[256];
   char targetpath[256];
   char authpath[16];
   char classicpath[256];
   sprintf(classicpath,"/var/run/ca/%s", source);

   if (quiet)
	{
	sprintf(authpath,"%s/%s", authie,devie); /* big brother is watching */
	target[0]=32; 
	if (slot==1)
		{
		target[1]=32; /* "  " */
		target[2]=0;
		}
	else
		{
		target[1]=0; /* " " */
		}
	sprintf(sourcepath, "%s/%s", authpath, source);
	sprintf(targetpath, "%s/%s", authpath, target);

	mkdir(authie, 0777);
       	mount("/", authie, NULL, MS_BIND, NULL);
	mkdir(authpath, 0777);

        /* create empty auth file at /var/run/ca for compatibility */
        auth_bin = fopen(targetpath, "r");
        if (auth_bin)
		{
		fclose(auth_bin);
   	       	auth_bin = fopen(classicpath, "r");
       		if (auth_bin > 0) /* already exists */
			{
			fclose(auth_bin);
			}
		else
			{
#ifdef RANDOM
			/* create file with random data */
 			FILE *f;
       	         	f=fopen (classicpath, "wb");
			int r,a;
			char c[1];
 			srand((unsigned)time(NULL));
			for(a=0;a<296;a++)
				{
				r=rand();
				c[0]=r;
				fwrite(c,1,1,f);
 				}
			fclose(f);
#else
			/* create empty file */
			int ff=open (classicpath, O_RDWR|O_CREAT,0);
			close(ff);
#endif
			}
		}
	else
		{
		/* no auth file hence remove compatibility file */
		remove(classicpath);
		}
	snprintf(dest, len, "%s/%s", authpath, target);
	}
   else
	{
	/* add module name to slot authorization bin file */
	strcpy(cin,ci_name);
	/* quickly replace blanks with _ */
	int i=0;
        while (cin[i] != 0)
	   {
           if (cin[i] == 32)
               cin[i]= 95; /* underscore _ */
	   i++;
           };

	strcpy(authpath,"/etc/enigma2"); /* standard authent file path */
	sprintf(target, "ci_auth_%s_%d.bin", cin, slot);
	sprintf(sourcepath, "%s/%s", authpath, source);
	sprintf(targetpath, "%s/%s", authpath, target);

	struct stat buf;
	char *linkname;

    	if (lstat(sourcepath, &buf) == 0) 
           {
           linkname = malloc(buf.st_size + 1);
           ret=readlink(sourcepath, linkname, buf.st_size);
           linkname[buf.st_size] = '\0';
	   if (ret == -1)
		{
		if (debug > 9) lprintf("READLINK %s error: %s\n",source,strerror(errno));
		linkname[0]=0;
		}
     	   if (debug > 10) lprintf("LINKNAME %s %d\n", linkname, strlen(linkname));
           if (strlen(linkname) > 0) /* file is link already */
		{
		if (strcmp(linkname,target) != 0)
			{
			/* link doesn't point to target hence correct */
			/* correct symlink */
		   	remove(sourcepath);
              	   	if (debug > 6) lprintf("CORRECTING %s to %s\n", target, source);
			ret=chdir(authpath);
	           	ret=symlink(target, source);
			if (ret)
				{
				if (debug > 0) lprintf("SYMLINK %s to %s error: %s\n",source,target,strerror(errno));
				}
                   	}
		}
           else /* file is not yet a link */
                {
                auth_bin = fopen(targetpath, "r");
                if (auth_bin)
	           {
                   /* if new file already exists and source is not symlink 
                      remove and do symlink */
	           fclose(auth_bin);
		   remove(sourcepath);
              	   if (debug > 6) lprintf("LINKING %s to %s\n", target, source);
		   ret=chdir(authpath);
	           ret= symlink(target, source);
		   if (ret)
			{
			if (debug > 0) lprintf("SYMLINK %s to %s error: %s\n",source,target,strerror(errno));
			}
                   }
		else
		   {
                   /* target doesn't exist needs migration   
	              which means rename old bin file without module name
                      to new file with module name and do symlink to old one */
                   if (debug > 6) lprintf("MIGRATING %s to %s\n", source, target);
	           rename(sourcepath,targetpath);
		   ret=chdir(authpath);
	           ret=symlink(target, source);
		   if (ret)
			{
			if (debug > 0) lprintf("SYMLINK %s to %s error: %s\n",source,target,strerror(errno));
                   	}
                   }
               }
           }
	else /* file is not a link */
	   {
           auth_bin = fopen(targetpath, "r");
           if (auth_bin)
	           {
                   /* if new file already exists and source is not there
                      simply do symlink */
	           fclose(auth_bin);
              	   if (debug > 6) lprintf("LINKING %s to %s\n", target, source);
		   ret=chdir(authpath);
	           ret=symlink(target, source);
		   if (ret)
			{
			if (debug > 0) lprintf("SYMLINK %s to %s error: %s\n",source,target,strerror(errno));
                   	}
		   }
           }
	snprintf(dest, len, "%s/ci_auth_%s_%d.bin", authpath, cin, slot);
	}
}

static bool get_authdata(uint8_t *host_id, uint8_t *dhsk, uint8_t *akh, unsigned int slot, unsigned int index)
{
	char filename[FILENAME_MAX];
	int fd;
	uint8_t chunk[8 + 256 + 32];
	unsigned int i;

	/* max pairs of data only */
	if (index > MAX_PAIRS)
		return false;

	get_authdata_filename(filename, sizeof(filename), slot);

	fd = open(filename, O_RDONLY);
	if (fd <= 0) {
		if (debug > 0) lprintf("can not open auth file\n");
		if (quiet)	
			{
			umount(authie);
			rmdir(authie);
			}
		return false;
	}

	for (i = 0; i < MAX_PAIRS; i++) {
		if (read(fd, chunk, sizeof(chunk)) != sizeof(chunk)) {
			if (debug > 0) lprintf("can not read auth data\n");
			close(fd);
			if (quiet)	
				{
				umount(authie);
				rmdir(authie);
				}
			return false;
		}

		if (i == index) {
			memcpy(host_id, chunk, 8);
			memcpy(dhsk, &chunk[8], 256);
			memcpy(akh, &chunk[8 + 256], 32);
			close(fd);
			if (quiet)	
				{
				umount(authie);
				rmdir(authie);
				}
			return true;
		}
	}

	close(fd);
	if (quiet)	
		{
		umount(authie);
		rmdir(authie);
		}
	return false;
}

static bool write_authdata(unsigned int slot, const uint8_t *host_id, const uint8_t *dhsk, const uint8_t *akh)
{
	char filename[FILENAME_MAX];
	int fd;
	uint8_t buf[(8 + 256 + 32) * MAX_PAIRS];
	unsigned int entries;
	unsigned int i;
	bool ret = false;

	for (entries = 0; entries < MAX_PAIRS; entries++) {
		int offset = (8 + 256 + 32) * entries;
		if (!get_authdata(&buf[offset], &buf[offset + 8], &buf[offset + 8 + 256], slot, entries))
			break;

		/* check if we got this pair already */
		if (!memcmp(&buf[offset + 8 + 256], akh, 32)) {
			if (debug > 0) lprintf("data already stored\n");
			return true;
		}
	}

	if (debug > 10) lprintf("GOT %d AUTH entries for writing\n", entries);

	get_authdata_filename(filename, sizeof(filename), slot);

	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd <= 0) {
		if (debug > 0) lprintf("can not open auth file for writing - auth data not stored\n");
		if (quiet)
			{
			umount(authie);
			rmdir(authie);
			}
		return false;
	}

	/* store new entry first */
	if (write(fd, host_id, 8) != 8) {
		if (debug > 0) lprintf("error in write host id\n");
		goto end;
	}

	if (write(fd, dhsk, 256) != 256) {
		if (debug > 0) lprintf("error in write dhsk\n");
		goto end;
	}

	if (write(fd, akh, 32) != 32) {
		if (debug > 0) lprintf("error in write akh\n");
		goto end;
	}

	/* skip the last one if exists */
	if (entries > 3)
		entries = 3;

	for (i = 0; i < entries; i++) {
		int offset = (8 + 256 + 32) * i;
		if (write(fd, &buf[offset], (8 + 256 + 32)) != (8 + 256 + 32)) {
			if (debug > 0) lprintf("error in write auth\n");
			goto end;
		}
	}

	ret = true;
end:
	close(fd);
	if (quiet)
		{
		umount(authie);
		rmdir(authie);
		}
	if (ret == true)
		{
		/* call once more to get symlink or compatibility file */
		get_authdata_filename(filename, sizeof(filename), slot);
		}
	if (quiet)
		{
		umount(authie);
		rmdir(authie);
		}
	return ret;
}

/* CI plus certificates */

struct cert_ctx {
	X509_STORE *store;

	/* Host */
	X509 *cust_cert;
	X509 *device_cert;

	/* Module */
	X509 *ci_cust_cert;
	X509 *ci_device_cert;
};

static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
	if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_CERT_NOT_YET_VALID) {
		time_t now = time(NULL);
		struct tm *t = localtime(&now);
		if (t->tm_year < 2016)
			{
			if (debug > 1) lprintf("seems our rtc is wrong - ignore!\n");
			return 1;
			}
	}

	if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_CERT_HAS_EXPIRED)
		return 1;
	return 0;
}

static RSA *rsa_privatekey_open(const char *filename)
{
	FILE *fp;
	RSA *r = NULL;

	fp = fopen(filename, "r");
	if (!fp) {
#ifndef EMBEDDED
		if (debug > 0) lprintf("can not open private key %s\n", filename);
#endif
		return NULL;
	}
	if (debug > 0) lprintf("EXTERNAL private key %s\n", filename);

	r=PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	if (!r)
		{
		if (debug > 0) lprintf("private key read error\n");
		}

	fclose(fp);
	return r;
}

static X509 *certificate_open(const char *filename)
{
	FILE *fp;
	X509 *cert;

	fp = fopen(filename, "r");
	if (!fp) {
#ifndef EMBEDDED
		if (debug > 0) lprintf("LOADING %s failed\n", filename);
#endif
		return NULL;
	}
	if (debug > 0) lprintf("EXTERNAL cert %s\n", filename);

	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	if (!cert)
		{
		if (debug > 0) lprintf("can not read certificate\n");
		}

	fclose(fp);

	return cert;
}

static bool certificate_validate(struct cert_ctx *ctx, X509 *cert)
{
	X509_STORE_CTX *store_ctx;
	int ret;

	store_ctx = X509_STORE_CTX_new();

	X509_STORE_CTX_init(store_ctx, ctx->store, cert, NULL);
	X509_STORE_CTX_set_verify_cb(store_ctx, verify_cb);
	X509_STORE_CTX_set_flags(store_ctx, X509_V_FLAG_IGNORE_CRITICAL);

	ret = X509_verify_cert(store_ctx);

	if (ret != 1)
		{
		if (debug > 0) lprintf("%s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(store_ctx)));
		}

	X509_STORE_CTX_free(store_ctx);

	return ret == 1;
}

static X509 *certificate_load_and_check(struct cert_ctx *ctx, const char *filename)
{
	X509 *cert;

	if (!ctx->store) {
		/* we assume this is the first certificate added, 
                   so it is the root-ca */
		ctx->store = X509_STORE_new();
		if (!ctx->store) {
			if (debug > 0) lprintf("can not create cert_store\n");
			return NULL;
		}

		if (X509_STORE_load_locations(ctx->store, filename, NULL) != 1) {
#ifndef EMBEDDED
			if (debug > 0) lprintf("LOADING %s failed\n", filename);
#endif
			return NULL;
		}
		if (debug > 0) lprintf("EXTERNAL cert %s\n", filename);

		return (X509 *) 1;
	}

	cert = certificate_open(filename);
	if (!cert) {
		return NULL;
	}

	if (!certificate_validate(ctx, cert)) {
		if (debug > 0) lprintf("can not vaildate certificate\n");
		X509_free(cert);
		return NULL;
	}

	/* push into store - create a chain */
	if (X509_STORE_load_locations(ctx->store, filename, NULL) != 1) {
#ifndef EMBEDDED
		if (debug > 0) lprintf("LOADING %s failed\n",filename);
#endif
		X509_free(cert);
		return NULL;
	}

	return cert;
}

static X509 *certificate_import_and_check(struct cert_ctx *ctx, const uint8_t *data, int len)
{
	X509 *cert;

	cert = d2i_X509(NULL, &data, len);
	if (!cert) {
		if (debug > 0) lprintf("can not read certificate\n");
		return NULL;
	}

	if (!certificate_validate(ctx, cert)) {
		if (debug > 0) lprintf("can not vaildate certificate\n");
		X509_free(cert);
		return NULL;
	}

	X509_STORE_add_cert(ctx->store, cert);

	return cert;
}

/* CI plus credentials */

#define MAX_ELEMENTS    33

uint32_t datatype_sizes[MAX_ELEMENTS] = {
	0, 50, 0, 0, 0, 8, 8, 0,
	0, 0, 0, 0, 32, 256, 256, 0,
	0, 256, 256, 32, 8, 8, 32, 32,
	0, 8, 2, 32, 1, 32, 1, 0,
	32
};

struct element {
	uint8_t *data;
	uint32_t size;
	/* buffer valid */
	bool valid;
};

struct cc_ctrl_data {
	/* parent */
	struct ci_session *session;

	/* ci+ credentials */
	struct element elements[MAX_ELEMENTS];

	/* DHSK */
	uint8_t dhsk[256];

	/* KS_host */
	uint8_t ks_host[32];

	/* derived keys */
	uint8_t sek[16];
	uint8_t sak[16];

	/* AKH checks - module performs 5 tries to get correct AKH */
	unsigned int akh_index;

	/* authentication data */
	uint8_t dh_exp[256];

	/* certificates */
	struct cert_ctx *cert_ctx;

	/* private key of device-cert */
	RSA *rsa_device_key;
};

static struct element *element_get(struct cc_ctrl_data *cc_data, unsigned int id)
{
	/* array index */
	if ((id < 1) || (id >= MAX_ELEMENTS)) {
		if (debug > 0) lprintf("element_get: invalid id\n");
		return NULL;
	}

	return &cc_data->elements[id];
}

static void element_invalidate(struct cc_ctrl_data *cc_data, unsigned int id)
{
	struct element *e;

	e = element_get(cc_data, id);
	if (e) {
		free(e->data);
		memset(e, 0, sizeof(struct element));
	}
}

static void element_init(struct cc_ctrl_data *cc_data)
{
	unsigned int i;

	for (i = 1; i < MAX_ELEMENTS; i++)
		element_invalidate(cc_data, i);
}

static bool element_set(struct cc_ctrl_data *cc_data, unsigned int id, const uint8_t *data, uint32_t size)
{
	struct element *e;

	e = element_get(cc_data, id);
	if (e == NULL)
		return false;

	/* check size */
	if ((datatype_sizes[id] != 0) && (datatype_sizes[id] != size)) {
		if (debug > 0) lprintf("size %d of datatype_id %d doesn't match\n", size, id);
		return false;
	}

	free(e->data);
	e->data = malloc(size);
	memcpy(e->data, data, size);
	e->size = size;
	e->valid = true;

	if (debug > 9) lprintf("stored %d with len %d\n", id, size);

	return true;
}

static bool element_set_certificate(struct cc_ctrl_data *cc_data, unsigned int id, X509 *cert)
{
	unsigned char *cert_der = NULL;
	int cert_len;

	cert_len = i2d_X509(cert, &cert_der);
	if (cert_len <= 0) {
		if (debug > 0) lprintf("can not get data in DER format\n");
		return false;
	}

	if (!element_set(cc_data, id, cert_der, cert_len)) {
		if (debug > 0) lprintf("can not store element (%d)\n", id);
		return false;
	}

	return true;
}

static bool element_set_hostid_from_certificate(struct cc_ctrl_data *cc_data, unsigned int id, X509 *cert)
{
	X509_NAME *subject;
	int nid_cn = OBJ_txt2nid("CN");
	char hostid[20];
	uint8_t bin_hostid[8];

	if ((id != 5) && (id != 6)) {
		if (debug > 0) lprintf("wrong datatype_id for hostid\n");
		return false;
	}

	subject = X509_get_subject_name(cert);
	X509_NAME_get_text_by_NID(subject, nid_cn, hostid, sizeof(hostid));

	if (strlen(hostid) != 16) {
		if (debug > 0) lprintf("malformed hostid\n");
		return false;
	}
	if (debug > 0) lprintf("HostID: %s\n",hostid);

	str2bin(bin_hostid, hostid, 16);

	if (!element_set(cc_data, id, bin_hostid, sizeof(bin_hostid))) {
		if (debug > 9) lprintf("can not set hostid\n");
		return false;
	}

	return true;
}

static bool element_valid(struct cc_ctrl_data *cc_data, unsigned int id)
{
	struct element *e;

	e = element_get(cc_data, id);

	return e && e->valid;
}

static unsigned int element_get_buf(struct cc_ctrl_data *cc_data, uint8_t *dest, unsigned int id)
{
	struct element *e;

	e = element_get(cc_data, id);
	if (e == NULL)
		return 0;

	if (!e->valid) {
		if (debug > 0) lprintf("element_get_buf: datatype %d not valid\n", id);
		return 0;
	}

	if (!e->data) {
		if (debug > 0) lprintf("element_get_buf: datatype %d doesn't exist\n", id);
		return 0;
	}

	if (dest)
		memcpy(dest, e->data, e->size);

	return e->size;
}

static unsigned int element_get_req(struct cc_ctrl_data *cc_data, uint8_t *dest, unsigned int id)
{
	unsigned int len = element_get_buf(cc_data, &dest[3], id);

	if (len == 0) {
		if (debug > 0) lprintf("can not get element %d\n", id);
		return 0;
	}

	dest[0] = id;
	dest[1] = len >> 8;
	dest[2] = len;

	return 3 + len;
}

static uint8_t *element_get_ptr(struct cc_ctrl_data *cc_data, unsigned int id)
{
	struct element *e;

	e = element_get(cc_data, id);
	if (e == NULL)
		return NULL;

	if (!e->valid) {
		if (debug > 0) lprintf("element_get_ptr: datatype %u not valid\n", id);
		return NULL;
	}

	if (!e->data) {
		if (debug > 0) lprintf("element_get_ptr: datatype %u doesn't exist\n", id);
		return NULL;
	}

	return e->data;
}


/* content_control commands */

static bool sac_check_auth(const uint8_t *data, unsigned int len, uint8_t *sak)
{
	struct aes_xcbc_mac_ctx ctx;
	uint8_t calced_signature[16];

	if (len < 16)
		{
		if (debug > 0) lprintf("auth too short\n");
		return false;
		}

	aes_xcbc_mac_init(&ctx, sak);
	aes_xcbc_mac_process(&ctx, (uint8_t *)"\x04", 1); /* header len */
	aes_xcbc_mac_process(&ctx, data, len - 16);
	aes_xcbc_mac_done(&ctx, calced_signature);

	if (memcmp(&data[len - 16], calced_signature, 16)) {
		if (debug > 0) lprintf("signature wrong\n");
		return false;
	}

	if (debug > 0) lprintf("auth ok!\n");
	return true;
}

static int sac_gen_auth(uint8_t *out, uint8_t *in, unsigned int len, uint8_t *sak)
{
	if (debug > 9) lprintf("sac_gen_auth\n");
	struct aes_xcbc_mac_ctx ctx;

	aes_xcbc_mac_init(&ctx, sak);
	aes_xcbc_mac_process(&ctx, (uint8_t *)"\x04", 1); /* header len */
	aes_xcbc_mac_process(&ctx, in, len);
	aes_xcbc_mac_done(&ctx, out);

	return 16;
}

static void generate_key_seed(struct cc_ctrl_data *cc_data)
{
	/* this is triggered by new ns_module */
	if (debug > 9) lprintf("generate_key_seed\n");

	/* generate new key_seed -> SEK/SAK key derivation */
	SHA256_CTX sha;

	SHA256_Init(&sha);
	SHA256_Update(&sha, &cc_data->dhsk[240], 16);
	SHA256_Update(&sha, element_get_ptr(cc_data, 22), element_get_buf(cc_data, NULL, 22));
	SHA256_Update(&sha, element_get_ptr(cc_data, 20), element_get_buf(cc_data, NULL, 20));
	SHA256_Update(&sha, element_get_ptr(cc_data, 21), element_get_buf(cc_data, NULL, 21));
	SHA256_Final(cc_data->ks_host, &sha);
}

static void generate_ns_host(struct cc_ctrl_data *cc_data)
{
	uint8_t buf[8];
	if (debug > 9) lprintf("generate_ns_host\n");
	get_random(buf, sizeof(buf));
	element_set(cc_data, 20, buf, sizeof(buf));
}

static int generate_SAK_SEK(uint8_t *sak, uint8_t *sek, const uint8_t *ks_host)
{
	AES_KEY key;
	const uint8_t key_data[16] = { 0xea, 0x74, 0xf4, 0x71, 0x99, 0xd7, 0x6f, 0x35, 0x89, 0xf0, 0xd1, 0xdf, 0x0f, 0xee, 0xe3, 0x00 };
	uint8_t dec[32];
	int i;
	if (debug > 9) lprintf("generate_SAK_SEK\n");

	/* key derivation of sak & sek */

	AES_set_encrypt_key(key_data, 128, &key);

	for (i = 0; i < 2; i++)
		AES_ecb_encrypt(&ks_host[16 * i], &dec[16 * i], &key, 1);

	for (i = 0; i < 16; i++)
		sek[i] = ks_host[i] ^ dec[i];

	for (i = 0; i < 16; i++)
		sak[i] = ks_host[16 + i] ^ dec[16 + i];

	return 0;
}

static int sac_crypt(uint8_t *dst, const uint8_t *src, unsigned int len, const uint8_t *key_data, int encrypt)
{
	uint8_t iv[16] = { 0xf7, 0x70, 0xb0, 0x36, 0x03, 0x61, 0xf7, 0x96, 0x65, 0x74, 0x8a, 0x26, 0xea, 0x4e, 0x85, 0x41 };
	AES_KEY key;
	if (debug > 9) lprintf("sac_crypt %d\n", encrypt);

	/* AES_ENCRYPT is '1' */

	if (encrypt)
		AES_set_encrypt_key(key_data, 128, &key);
	else
		AES_set_decrypt_key(key_data, 128, &key);

	AES_cbc_encrypt(src, dst, len, &key, iv, encrypt);

	return 0;
}

static X509 *import_ci_certificates(struct cc_ctrl_data *cc_data, unsigned int id)
{
	struct cert_ctx *ctx = cc_data->cert_ctx;
	X509 *cert;
	uint8_t buf[2048];
	unsigned int len;
	if (debug > 9) lprintf("import_ci_certificates\n");

	len = element_get_buf(cc_data, buf, id);

	cert = certificate_import_and_check(ctx, buf, len);
	if (!cert) {
		if (debug > 0) lprintf("can not read/verify DER cert\n");
		return NULL;
	}

	return cert;
}

static int check_ci_certificates(struct cc_ctrl_data *cc_data)
{
	struct cert_ctx *ctx = cc_data->cert_ctx;

	/* check if both certificates are available before we push and verify them */

	/* check for CICAM_BrandCert */
	if (!element_valid(cc_data, 8))
		{
                if (debug > 9) lprintf("brand cert invalid\n");
		return -1;
		}

	/* check for CICAM_DevCert */
	if (!element_valid(cc_data, 16))
		{
                if (debug > 9) lprintf("device cert invalid\n");
		return -1;
		}

	if (extract_ci_cert)
		{
		/* write ci device cert to disk */
		char ci_cert_file[64];
		sprintf(ci_cert_file,"/etc/enigma2/ci_cert_%s_%d.der", ci_name_underscore, ci_number);
                if (debug > 0) lprintf("CI%d EXTRACTING %s\n", ci_number, ci_cert_file);
		int fd = open(ci_cert_file, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
		int ret = write(fd, element_get_ptr(cc_data, 16), element_get_buf(cc_data, NULL, 16));
		if (ret)
			{
   			if (debug > 0) lprintf("write cert error: %s\n",strerror(errno)); 
			}
		close(fd);
		/* display strings in der cert file */
		cert_strings(ci_cert_file);
		}

	/* import CICAM_BrandCert */
	if ((ctx->ci_cust_cert = import_ci_certificates(cc_data, 8)) == NULL) {
		if (debug > 0) lprintf("can not import brand cert\n");
		return -1;
	}

	/* import CICAM_DevCert */
	if ((ctx->ci_device_cert = import_ci_certificates(cc_data, 16)) == NULL) {
		if (debug > 0) lprintf("can not import device cert\n");
		return -1;
	}

	/* everything seems to be fine here - so extract the CICAM_id from cert */
	if (!element_set_hostid_from_certificate(cc_data, 6, ctx->ci_device_cert)) {
		if (debug > 0) lprintf("can not set cicam_id in elements\n");
		return -1;
	}

	return 0;
}

static int generate_akh(struct cc_ctrl_data *cc_data)
{
	uint8_t akh[32];
	SHA256_CTX sha;

	SHA256_Init(&sha);
	SHA256_Update(&sha, element_get_ptr(cc_data, 6), element_get_buf(cc_data, NULL, 6));
	SHA256_Update(&sha, element_get_ptr(cc_data, 5), element_get_buf(cc_data, NULL, 5));
	SHA256_Update(&sha, cc_data->dhsk, 256);
	SHA256_Final(akh, &sha);

	element_set(cc_data, 22, akh, sizeof(akh));

	return 0;
}

static bool check_dh_challenge(struct cc_ctrl_data *cc_data)
{
	/* check if every element for calculation of DHSK & AKH is available */
	if (debug > 5) lprintf("checking ...\n");

	/* check for auth_nonce */
	if (!element_valid(cc_data, 19))
		{
                if (debug > 9) lprintf("auth nonce invalid\n");
		return false;
		}

	/* check for CICAM_id */
	if (!element_valid(cc_data, 6))
		{
                if (debug > 9) lprintf("cicam id invalid\n");
		return false;
		}

	/* check for DHPM */
	if (!element_valid(cc_data, 14))
		{
                if (debug > 9) lprintf("dphm invalid\n");
		return false;
		}

	/* check for Signature_B */
	if (!element_valid(cc_data, 18))
		{
                if (debug > 9) lprintf("signature B invalid\n");
		return false;
		}

	/* calculate DHSK - DHSK = DHPM ^ dh_exp % dh_p */
	dh_mod_exp(cc_data->dhsk, 256, element_get_ptr(cc_data, 14), 256, dh_p, sizeof(dh_p), cc_data->dh_exp, 256);

	/* gen AKH */
	generate_akh(cc_data);

	/* disable 5 tries of startup -> use new calculated one */
	cc_data->akh_index = MAX_PAIRS;

	if (debug > 6) lprintf("writing authdata ...\n");
	/* write to disk */
	write_authdata(cc_data->session->slot_index, element_get_ptr(cc_data, 5), cc_data->dhsk, element_get_ptr(cc_data, 22));

	return true;
}

static int restart_dh_challenge(struct cc_ctrl_data *cc_data)
{
	uint8_t dhph[256], sign_A[256];
	struct cert_ctx *ctx;
	if (debug > 5) lprintf("RECHECKING certs ...\n");

	if (!cc_data->cert_ctx) {
		ctx = calloc(1, sizeof(struct cert_ctx));
		cc_data->cert_ctx = ctx;
	} else {
		ctx = cc_data->cert_ctx;
	}

	/* load certificates and device key */
	if (!certificate_load_and_check(ctx, "/etc/ssl/certs/root.pem"))
		{
#ifdef EMBEDDED
		/* internal root certificate handling */
		root_cert_len=strlen(root_cert);
		root_bio = BIO_new(BIO_s_mem());
		BIO_write(root_bio, root_cert, root_cert_len);
		X509* root_certX509 = PEM_read_bio_X509(root_bio, NULL, NULL, NULL);
		if (!root_certX509) 
			{
    			if (debug > 9) lprintf("FAILED parsing embedded root cert\n");
			}
		if (!ctx->store) 
			{
			ctx->store = X509_STORE_new();
			if (!ctx->store) 
				{
				if (debug > 9) lprintf("can not create cert_store\n");
				}
			}
    		if (debug > 9) lprintf("EMBEDDED root cert ...\n");
		X509_STORE_add_cert(ctx->store, root_certX509);
#endif
		}
	ctx->cust_cert = certificate_load_and_check(ctx, "/etc/ssl/certs/customer.pem");
#ifdef EMBEDDED
	if (!ctx->cust_cert)
		{
		/* internal customer certificate handling */
		customer_cert_len=strlen(customer_cert);
		customer_bio = BIO_new(BIO_s_mem());
		BIO_write(customer_bio, customer_cert, customer_cert_len);
		X509* customer_certX509 = PEM_read_bio_X509(customer_bio, NULL, NULL, NULL);
		if (!customer_certX509) 
			{
    			if (debug > 9) lprintf("FAILED parsing embedded customer cert\n");
			}
    		if (debug > 9) lprintf("EMBEDDED customer cert ...\n");
		X509_STORE_add_cert(ctx->store, customer_certX509);
		ctx->cust_cert=customer_certX509;
		}
#endif
	ctx->device_cert = certificate_load_and_check(ctx, "/etc/ssl/certs/device.pem");
#ifdef EMBEDDED
	if (!ctx->device_cert)
		{
		/* internal device certificate handling */
		device_cert_len=strlen(device_cert);
		device_bio = BIO_new(BIO_s_mem());
		BIO_write(device_bio, device_cert, device_cert_len);
		X509* device_certX509 = PEM_read_bio_X509(device_bio, NULL, NULL, NULL);
		if (!device_certX509) 
			{
    			if (debug > 9) lprintf("FAILED parsing embedded device cert\n");
			}
    		if (debug > 9) lprintf("EMBEDDED device cert ...\n");
		X509_STORE_add_cert(ctx->store, device_certX509);
		ctx->device_cert=device_certX509;
		}
#endif
	if (!ctx->cust_cert || !ctx->device_cert) 
		{
		if (debug > 0) lprintf("can not check loader certificates\n");
		return -1;
		}

	/* add data to element store */
	if (!element_set_certificate(cc_data, 7, ctx->cust_cert))
		if (debug > 0) lprintf("can not store cert in elements\n");

	if (!element_set_certificate(cc_data, 15, ctx->device_cert))
		if (debug > 0) lprintf("can not store cert in elements\n");

	if (!element_set_hostid_from_certificate(cc_data, 5, ctx->device_cert))
		if (debug > 0) lprintf("can not set hostid in elements\n");

	cc_data->rsa_device_key = rsa_privatekey_open("/etc/ssl/certs/device.pem");
	if (!cc_data->rsa_device_key)
		{
#ifdef EMBEDDED
		/* internal private key */
		cc_data->rsa_device_key = PEM_read_bio_RSAPrivateKey(device_bio,NULL, NULL, NULL);
    		if (debug > 9) lprintf("EMBEDDED private key ...\n");
#else
		if (debug > 0) lprintf("can not read private key\n");
		return -1;
#endif
		}

	/* invalidate elements */
	element_invalidate(cc_data, 6);
	element_invalidate(cc_data, 14);
	element_invalidate(cc_data, 18);
	element_invalidate(cc_data, 22); /* this will refuse a unknown cam */

	/* new dh_exponent */
	dh_gen_exp(cc_data->dh_exp, 256, dh_g, sizeof(dh_g), dh_p, sizeof(dh_p));

	/* new DHPH  - DHPH = dh_g ^ dh_exp % dh_p */
	dh_mod_exp(dhph, sizeof(dhph), dh_g, sizeof(dh_g), dh_p, sizeof(dh_p), cc_data->dh_exp, 256);

	/* store DHPH */
	element_set(cc_data, 13, dhph, sizeof(dhph));

	/* create Signature_A */
	dh_dhph_signature(sign_A, element_get_ptr(cc_data, 19), dhph, cc_data->rsa_device_key);

	/* store Signature_A */
	element_set(cc_data, 17, sign_A, sizeof(sign_A));

	return 0;
}

static int generate_uri_confirm(struct cc_ctrl_data *cc_data, const uint8_t *sak)
{
	SHA256_CTX sha;
	uint8_t uck[32];
	uint8_t uri_confirm[32];

	/* calculate UCK (uri confirmation key) */
	SHA256_Init(&sha);
	SHA256_Update(&sha, sak, 16);
	SHA256_Final(uck, &sha);

	/* calculate uri_confirm */
	SHA256_Init(&sha);
	SHA256_Update(&sha, element_get_ptr(cc_data, 25), element_get_buf(cc_data, NULL, 25));
	SHA256_Update(&sha, uck, 32);
	SHA256_Final(uri_confirm, &sha);

	element_set(cc_data, 27, uri_confirm, 32);

	return 0;
}

static void check_new_key(struct cc_ctrl_data *cc_data)
{
	const uint8_t s_key[16] = { 0x3e, 0x20, 0x15, 0x84, 0x2c, 0x37, 0xce, 0xe3, 0xd6, 0x14, 0x57, 0x3e, 0x3a, 0xab, 0x91, 0xb6 };
	AES_KEY aes_ctx;
	uint8_t dec[32];
	uint8_t *kp;
	uint8_t slot;
	unsigned int i;
	if (debug > 5) lprintf("key checking ...\n");

	/* check for keyprecursor */
	if (!element_valid(cc_data, 12))
		{
                if (debug > 9) lprintf("key precursor invalid\n");
		return;
		}

	/* check for slot */
	if (!element_valid(cc_data, 28))
		{
                if (debug > 9) lprintf("slot invalid\n");
		return;
		}

	kp = element_get_ptr(cc_data, 12);
	element_get_buf(cc_data, &slot, 28);

	AES_set_encrypt_key(s_key, 128, &aes_ctx);
	for (i = 0; i < 32; i += 16)
		AES_ecb_encrypt(&kp[i], &dec[i], &aes_ctx, 1);

	for (i = 0; i < 32; i++)
		dec[i] ^= kp[i];

	descrambler_set_key(cc_data->session->slot_index, slot, dec);

	/* reset */
	element_invalidate(cc_data, 12);
	element_invalidate(cc_data, 28);
}

static int data_get_handle_new(struct cc_ctrl_data *cc_data, unsigned int id)
{
	/* handle trigger events */
	/* depends on new received items */

	switch (id) {
	case 8:         /* CICAM_BrandCert */
	case 14:        /* DHPM */
	case 16:        /* CICAM_DevCert */
//	case 6: 	/* CICAM_id */
	case 18:        /* Signature_B */
			/* this results in CICAM_ID when cert-chain 
			   is verified and ok */
		if (check_ci_certificates(cc_data))
			break;
		/* generate DHSK & AKH */
		check_dh_challenge(cc_data);
		break;

	case 19:        /* auth_nonce - triggers new dh keychallenge 
				      - invalidates DHSK & AKH */

		/* generate DHPH & Signature_A */
		restart_dh_challenge(cc_data);
		break;

	case 21:        /* Ns_module - triggers SAC key calculation */
		generate_ns_host(cc_data);
		generate_key_seed(cc_data);
		generate_SAK_SEK(cc_data->sak, cc_data->sek, cc_data->ks_host);
		break;

	/* SAC data messages */
	case 6: 	/* CICAM_id */
	case 12:        /* keyprecursor */
	case 28:        /* key register */
		check_new_key(cc_data);
		break;
	case 26:        /* unknown */
		break;
	case 25:        /* uri_message */
		if (debug > 9) lprintf("uri message\n");
		generate_uri_confirm(cc_data, cc_data->sak);
		break;
	default:
		if (debug > 5) lprintf("unhandled id %d\n", id);
		break;
	}

	return 0;
}

static int data_req_handle_new(struct cc_ctrl_data *cc_data, unsigned int id)
{
	switch (id) {
	case 22:                /* AKH */
	{
		// printf("AKH 22\n");
		uint8_t akh[32], host_id[8];
		memset(akh, 0, sizeof(akh));
		if (cc_data->akh_index != 5) {
			if (!get_authdata(host_id, cc_data->dhsk, akh, cc_data->session->slot_index, cc_data->akh_index++))
				cc_data->akh_index = 5;
			if (!element_set(cc_data, 22, akh, 32))
				if (debug > 0) lprintf("can not set AKH in elements\n");
			if (!element_set(cc_data, 5, host_id, 8))
				if (debug > 0) lprintf("can not set host_id in elements\n");
		}
	}
	default:
		// printf("NO AKH\n");
		break;
	}

	return 0;
}

static int data_get_loop(struct cc_ctrl_data *cc_data, const unsigned char *data, unsigned int datalen, unsigned int items)
{
	unsigned int i;
	int dt_id, dt_len;
	unsigned int pos = 0;

	for (i = 0; i < items; i++) {
		if (pos + 3 > datalen)
			{
			if (debug > 2) lprintf("set element too short\n");
			return 0;
			}

		dt_id = data[pos++];
		dt_len = data[pos++] << 8;
		dt_len |= data[pos++];

		if (pos + dt_len > datalen)
			{
			if (debug > 2) lprintf("set element too long\n");
			return 0;
			}

		if (debug > 2) lprintf("set element %d\n", dt_id);
		if (debug > 4) hexdump(&data[pos], dt_len);
		element_set(cc_data, dt_id, &data[pos], dt_len);

		data_get_handle_new(cc_data, dt_id);

		pos += dt_len;
	}

	return pos;
}

static int data_req_loop(struct cc_ctrl_data *cc_data, unsigned char *dest, const unsigned char *data, unsigned int datalen, unsigned int items)
{
	int dt_id;
	unsigned int i;
	int pos = 0;
	int len;

	if (items > datalen)
		return -1;

	for (i = 0; i < items; i++) {
		dt_id = *data++;
		if (debug > 2) lprintf("req element %d\n", dt_id);
		data_req_handle_new(cc_data, dt_id);    /* check if there is any action needed before we answer */
		len = element_get_req(cc_data, dest, dt_id);
		if (len == 0) {
			if (debug > 0) lprintf("can not get element %d\n", dt_id);
			return -1;
		}
		pos += len;
		dest += len;
	}
	return pos;
}

static bool data_initialize(struct ci_session *session)
{
	struct cc_ctrl_data *data;
	uint8_t buf[32], host_id[8];

	if (session->private_data) {
		if (debug > 0) lprintf("strange private_data not null!\n");
		return false;
	}

	data = calloc(1, sizeof(struct cc_ctrl_data));
	if (!data) {
		if (debug > 0) lprintf("out of memory\n");
		return false;
	}

	/* parent */
	data->session = session;

	/* clear storage of credentials */
	element_init(data);

	/* set status field - OK */
	memset(buf, 0, 1);
	if (!element_set(data, 30, buf, 1)) {
		if (debug > 0) lprintf("can not set status in elements\n");
		}

	/* set uri versions */
	memset(buf, 0, 32);
	buf[31] = uri_version;

        if (debug > 9) lprintf("uri version set to %d\n", buf[31]);
	if (!element_set(data, 29, buf, 32)) 
		{
		if (debug > 0) lprintf("can not set uri version in elements\n");
		}

	/* load first AKH */
	data->akh_index = 0;
	if (!get_authdata(host_id, data->dhsk, buf, session->slot_index, data->akh_index)) {
		/* no AKH available */
		memset(buf, 0, sizeof(buf));
		data->akh_index = 5;    /* last one */
	}

	if (!element_set(data, 22, buf, 32))
		{
		if (debug > 0) lprintf("can not set AKH in elements\n");
		}

	if (!element_set(data, 5, host_id, 8))
		{
		if (debug > 0) lprintf("can not set host_id elements\n");
		}

	session->private_data = data;

	return true;
}


static void ci_ccmgr_cc_open_cnf(struct ci_session *session)
{
	const uint8_t tag[3] = { 0x9f, 0x90, 0x02 };
	const uint8_t bitmap = 0x01;

	data_initialize(session);

	ci_session_sendAPDU(session, tag, &bitmap, 1);
}

static bool ci_ccmgr_cc_data_req(struct ci_session *session, const uint8_t *data, unsigned int len)
{
	struct cc_ctrl_data *cc_data = session->private_data;
	uint8_t cc_data_cnf_tag[3] = { 0x9f, 0x90, 0x04 };
	uint8_t dest[2048 * 2];
	int dt_nr;
	int id_bitmask;
	int answ_len;
	unsigned int rp = 0;

	if (len < 2)
		{
		if (debug > 0) lprintf("req data too short\n");
		return false;
		}

	id_bitmask = data[rp++];

	/* handle data loop */
	dt_nr = data[rp++];
	rp += data_get_loop(cc_data, &data[rp], len - rp, dt_nr);

	if (len < rp + 1) 
		{
		if (debug > 0) lprintf("req data too short\n");
		return false;
		}

	/* handle req_data loop */
	dt_nr = data[rp++];

	dest[0] = id_bitmask;
	dest[1] = dt_nr;

	answ_len = data_req_loop(cc_data, &dest[2], &data[rp], len - rp, dt_nr);
	if (answ_len <= 0) 
		{
		if (debug > 0) lprintf("can not req data\n");
		return false;
		}

	answ_len += 2;

	ci_session_sendAPDU(session, cc_data_cnf_tag, dest, answ_len);

	return true;
}

static bool ci_ccmgr_cc_sac_send(struct ci_session *session, const uint8_t *tag, uint8_t *data, unsigned int pos)
{
	struct cc_ctrl_data *cc_data = session->private_data;

	if (pos < 8)
		{
		if (debug > 0) lprintf("too short sac data\n");
		return false;
		}

	pos += add_padding(&data[pos], pos - 8, 16);
	BYTE16(&data[6], pos - 8);      /* len in header */

	pos += sac_gen_auth(&data[pos], data, pos, cc_data->sak);
	sac_crypt(&data[8], &data[8], pos - 8, cc_data->sek, AES_ENCRYPT);

	ci_session_sendAPDU(session, tag, data, pos);

	return true;
}

static bool ci_ccmgr_cc_sac_data_req(struct ci_session *session, const uint8_t *data, unsigned int len)
{
	struct cc_ctrl_data *cc_data = session->private_data;
	const uint8_t data_cnf_tag[3] = { 0x9f, 0x90, 0x08 };
	uint8_t dest[2048];
	uint8_t tmp[len];
	int id_bitmask, dt_nr;
	unsigned int serial;
	int answ_len;
	int pos = 0;
	unsigned int rp = 0;

	if (len < 10)
		return false;

	if (debug > 0) lprintf("cc_sac_data_req\n");
	if (debug >4) hexdump(data, len);

	memcpy(tmp, data, 8);
	sac_crypt(&tmp[8], &data[8], len - 8, cc_data->sek, AES_DECRYPT);
	data = tmp;

	if (!sac_check_auth(data, len, cc_data->sak)) {
		if (debug > 0) lprintf("check_auth of message failed\n");
		return false;
	}

	serial = UINT32(&data[rp], 4);
	if (debug > 9) lprintf("serial sac data req: %d\n", serial);

	/* skip serial & header */
	rp += 8;

	id_bitmask = data[rp++];

	/* handle data loop */
	dt_nr = data[rp++];
	rp += data_get_loop(cc_data, &data[rp], len - rp, dt_nr);

	if (len < rp + 1)
		{
		if (debug > 0) lprintf("check_auth of message too short\n");
		return false;
		}

	dt_nr = data[rp++];

	/* create answer */
	pos += BYTE32(&dest[pos], serial);
	pos += BYTE32(&dest[pos], 0x01000000);

	dest[pos++] = id_bitmask;
	dest[pos++] = dt_nr;    /* dt_nbr */

	answ_len = data_req_loop(cc_data, &dest[pos], &data[rp], len - rp, dt_nr);
	if (answ_len <= 0) {
		if (debug > 0) lprintf("can not req data\n");
		return false;
	}
	pos += answ_len;

	if (debug > 0) lprintf("send req data\n");
	return ci_ccmgr_cc_sac_send(session, data_cnf_tag, dest, pos);
}

static void ci_ccmgr_pin_capabilities_req(struct ci_session *session)
{
	if (debug > 0) lprintf("UNKNOWN cc_sac_pin_capabilities\n");
	return;
}

static void ci_ccmgr_pin_event_reply(struct ci_session *session)
{
	if (debug > 0) lprintf("UNKNOWN cc_sac_pin_event_reply\n");
	return;
}

static void ci_ccmgr_cc_sac_sync_req(struct ci_session *session, const uint8_t *data, unsigned int len)
{
	const uint8_t sync_cnf_tag[3] = { 0x9f, 0x90, 0x10 };
	uint8_t dest[64];
	unsigned int serial;
	int pos = 0;

	if (debug > 0) lprintf("cc_sac_sync_req\n");
	if (debug >4) hexdump(data, len);

	serial = UINT32(data, 4);
	if (debug > 9) lprintf("serial sac sync req: %d\n", serial);

	pos += BYTE32(&dest[pos], serial);
	pos += BYTE32(&dest[pos], 0x01000000);

	/* status OK */
	dest[pos++] = 0;

	ci_ccmgr_cc_sac_send(session, sync_cnf_tag, dest, pos);
}


static void ci_ccmgr_cc_sync_req(struct ci_session *session, const uint8_t *data, unsigned int len)
{
	const uint8_t tag[3] = { 0x9f, 0x90, 0x06 };
	const uint8_t status = 0x00;    /* OK */

	ci_session_sendAPDU(session, tag, &status, 1);
}

static int ci_ccmgr_receive(struct ci_session *session, const uint8_t *tag, const uint8_t *data, unsigned int len)
{
	if (debug > 5) lprintf("content_control %02x %02x %02x\n", tag[0], tag[1], tag[2]);

	if ((tag[0] == 0x9f) && (tag[1] == 0x90)) {
		switch (tag[2]) {
		case 0x01: ci_ccmgr_cc_open_cnf(session); break;
		case 0x03: ci_ccmgr_cc_data_req(session, data, len); break;
		case 0x05: ci_ccmgr_cc_sync_req(session, data, len); break;
		case 0x07: ci_ccmgr_cc_sac_data_req(session, data, len); break;
		case 0x09: ci_ccmgr_cc_sac_sync_req(session, data, len); break;
		case 0x12: ci_ccmgr_pin_capabilities_req(session); break;
		case 0x14: ci_ccmgr_pin_event_reply(session); break;
		case 0x15: ci_ccmgr_pin_event_reply(session); break;
		default:
			if (debug > 0) lprintf("unknown apdu tag %02x\n", tag[2]);
			break;
		}
	}
	return 0;
}

static void ci_ccmgr_doAction(struct ci_session *session)
{
	if (debug > 2) lprintf("ccmgr_doAction()\n");

	switch (session->state) {
	case started:
		session->action = 0;
		break;
	case ProfileEnquiry:
	{
		const uint8_t tag[3] = { 0x9f, 0x90, 0x02 };
		const uint8_t data = 0x01;
		ci_session_sendAPDU(session, tag, &data, 1);
		session->state = Final;
		session->action = 0;
		break;
	}
	default:
		if (debug > 0) lprintf("unknown default state\n");
		break;
	}
}

static void ci_ccmgr_doClose(struct ci_session *session)
{
	struct cc_ctrl_data *data = session->private_data;

	if (debug > 2) lprintf("close content_control\n");

	element_init(data);
	free(data);
	session->private_data = NULL;
}

const struct ci_resource resource_content_ctrl1 = {
	.id = 0x8c1001,
	.receive = ci_ccmgr_receive,
	.doAction = ci_ccmgr_doAction,
	.doClose = ci_ccmgr_doClose,
};

const struct ci_resource resource_content_ctrl2 = {
	.id = 0x8c1002,
	.receive = ci_ccmgr_receive,
	.doAction = ci_ccmgr_doAction,
	.doClose = ci_ccmgr_doClose,
};
