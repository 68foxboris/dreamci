#ifndef __SESSION_H_
#define __SESSION_H_

enum session_state {
	unused,
	inCreation,
	started,
	inDeletion,

	/* this sucks - need own states for every resource */

	/* res_mgr */
	FirstProfileEnquiry,
	ProfileChange,
	ProfileEnquiry,
	Final,
	/* dt_mgr */
	senddatetime,
};

struct ci_session {
	/* parent */
	struct ci_module *ci;

	/* slot index */
	uint32_t slot_index;

	uint16_t index;

	uint32_t resid;

	enum session_state state;

	int action;

	/* resources */
	const struct ci_resource *resource;

	/* private data */
	void *private_data;
};

void ci_session_sendAPDU(struct ci_session *session, const uint8_t *tag, const uint8_t *data, size_t len);
void ci_session_set_app_name(struct ci_session *session, const uint8_t *data, size_t len);

#endif
