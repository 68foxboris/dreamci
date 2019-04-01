#ifndef __RESOURCE_H_
#define __RESOURCE_H_

#include <stdbool.h>
#include <stdint.h>

struct ci_session;

struct ci_resource {
	uint32_t id;
	bool (*init)(void);
	int (*receive)(struct ci_session *session, const uint8_t *tag, const uint8_t *data, unsigned int len);
	void (*doAction)(struct ci_session *session);
	void (*doClose)(struct ci_session *session);
};

extern const struct ci_resource
	resource_app_info1,
	resource_app_info2,
	resource_app_info3,
	resource_ca_support,
	resource_host_ctrl1,
	resource_host_ctrl2,
	resource_datetime,
	resource_mmi,
	resource_app_mmi1,
	resource_app_mmi2,
	resource_content_ctrl1,
	resource_content_ctrl2,
	resource_host_lac,
	resource_cam_upgrade,
	resource_multi_crypt;
#endif
