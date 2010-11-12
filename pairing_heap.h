// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef PAIRING_HEAP_H
#define PAIRING_HEAP_H

/* Algorithm: see http://en.wikipedia.org/wiki/Pairing_heap
 * This is just an efficient translation from recursive to iterative form.
 *
 * Note: find_min() is so trivial that we don't implement it.
 */

/* generic version: KEYDEF is kept separate, allowing you to
 * embed this structure into other container structures already
 * possessing some key (just provide an empty KEYDEF in this case).
 */
#define _PAIRING_HEAP_TYPEDEF(KEYTYPE,KEYDEF)		\
							\
struct pairing_heap_##KEYTYPE {			        \
	KEYDEF						\
	struct pairing_heap_##KEYTYPE *next;	        \
	struct pairing_heap_##KEYTYPE *subheaps;	\
};

/* less generic version: define the key inside.
 */
#define PAIRING_HEAP_TYPEDEF(KEYTYPE)			\
	_PAIRING_HEAP_TYPEDEF(KEYTYPE, KEYTYPE key;)

/* generic methods: allow arbitrary CMP() functions.
 */
#define _PAIRING_HEAP_FUNCTIONS(_STATIC,KEYTYPE,CMP)			\
									\
_STATIC								        \
struct pairing_heap_##KEYTYPE *_ph_merge_##KEYTYPE(struct pairing_heap_##KEYTYPE *heap1, struct pairing_heap_##KEYTYPE *heap2) \
{									\
	if (!heap1)							\
		return heap2;						\
	if (!heap2)							\
		return heap1;						\
	if (CMP(heap1, heap2)) {						\
		heap2->next = heap1->subheaps;				\
		heap1->subheaps = heap2;				\
		return heap1;						\
	}								\
	heap1->next = heap2->subheaps;					\
	heap2->subheaps = heap1;					\
	return heap2;							\
}									\
									\
_STATIC								        \
void ph_insert_##KEYTYPE(struct pairing_heap_##KEYTYPE **heap, struct pairing_heap_##KEYTYPE *new) \
{									\
	new->next = NULL;						\
	new->subheaps = NULL;						\
	*heap = _ph_merge_##KEYTYPE(*heap, new);			\
}									\
									\
_STATIC								        \
void ph_delete_min_##KEYTYPE(struct pairing_heap_##KEYTYPE **heap)	\
{									\
	struct pairing_heap_##KEYTYPE *tmplist = NULL;			\
	struct pairing_heap_##KEYTYPE *ptr;				\
	struct pairing_heap_##KEYTYPE *next;				\
	struct pairing_heap_##KEYTYPE *res;				\
	if (!*heap) {							\
		return;							\
	}								\
	for (ptr = (*heap)->subheaps; ptr; ptr = next) {			\
		struct pairing_heap_##KEYTYPE *p2 = ptr->next;		\
		next = p2;						\
		if (p2) {						\
			next = p2->next;				\
			ptr = _ph_merge_##KEYTYPE(ptr, p2);		\
		}							\
		ptr->next = tmplist;					\
		tmplist = ptr;						\
	}								\
	res = NULL;							\
	for (ptr = tmplist; ptr; ptr = next) {				\
		next = ptr->next;					\
		res = _ph_merge_##KEYTYPE(res, ptr);			\
	}								\
	*heap = res;							\
}

/* some default CMP() function */
#define PAIRING_HEAP_COMPARE(a,b) ((a)->key < (b)->key)

/* less generic version: use the default CMP() function */
#define PAIRING_HEAP_FUNCTIONS(_STATIC,KEYTYPE)				\
	_PAIRING_HEAP_FUNCTIONS(_STATIC,KEYTYPE,PAIRING_HEAP_COMPARE)

#endif
