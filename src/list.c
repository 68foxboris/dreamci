#include <search.h>
#include "list.h"

void _list_add_tail(struct list_head **list, void *_e)
{
	struct list_head *e = _e;

	assert(list != NULL);
	assert(e != NULL);

	if (*list == NULL) {
		e->next = e;
		e->prev = e;
		insque(e, e);
		*list = e;
	} else {
		insque(e, (*list)->prev);
	}
}

void _list_del(struct list_head **list, void *_e)
{
	struct list_head *e = _e;

	assert(list != NULL);
	assert(*list != NULL);
	assert(e != NULL);

	if (e->next == e)
		*list = NULL;
	else if (*list == e)
		*list = e->next;

	remque(e);
}
