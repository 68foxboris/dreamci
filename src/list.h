#ifndef __LIST_H_
#define __LIST_H_

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

void _list_add_tail(struct list_head **list, void *_e);
void _list_del(struct list_head **list, void *_e);

#define list_init(_e)                                   \
	do {                                                    \
		assert(offsetof(typeof(*(_e)), list) == 0);     \
		struct list_head *ck = &(_e)->list;             \
		ck->next = NULL;                                \
		ck->prev = NULL;                                \
	} while (0)

#define list_add_tail(_list, _e)                        \
	do {                                                    \
		assert(offsetof(typeof(*(_e)), list) == 0);     \
		struct list_head *ck = &(_e)->list;             \
		(void)ck;                                       \
		_list_add_tail((_list), (_e));                  \
	} while (0)

#define list_del(_list, _e)                             \
	do {                                                    \
		assert(offsetof(typeof(*(_e)), list) == 0);     \
		struct list_head *ck = &(_e)->list;             \
		(void)ck;                                       \
		_list_del((_list), (_e));                       \
	} while (0)

#define list_pop_front(_list, _type)                    \
	({                                                      \
		assert(offsetof(_type, list) == 0);             \
		struct list_head *ck = &((_type *)0)->list;     \
		(void)ck;                                       \
		struct list_head *front = *_list;               \
		_list_del(_list, front);                        \
		(_type *)front;                                 \
	})

#define list_for_each(_e, _list)                        \
	for (const struct list_head *it = (_list); it != NULL && ((_e) = (void *)it); it = (it->next == (_list)) ? NULL : it->next)

static inline bool list_empty(const struct list_head *list)
{
	return list == NULL;
}

#endif
