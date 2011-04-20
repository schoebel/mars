// (c) 2011 Thomas Schoebel-Theuer / 1&1 Internet AG

#ifndef LIB_QUEUE_H
#define LIB_QUEUE_H

#define QUEUE_ANCHOR(PREFIX,KEYTYPE,HEAPTYPE)		\
	spinlock_t q_lock;				\
	struct list_head q_anchor;			\
	struct pairing_heap_##HEAPTYPE *heap_high;	\
	struct pairing_heap_##HEAPTYPE *heap_low;	\
	long long q_last_insert; /* jiffies */		\
	KEYTYPE heap_margin;				\
	KEYTYPE last_pos;				\
	/* parameters */				\
	atomic_t *q_contention;				\
	struct PREFIX##_queue *q_dep;			\
	bool q_barrier;					\
	/* readonly from outside */			\
	atomic_t q_queued;				\
	atomic_t q_flying;				\
	atomic_t q_total;				\
	/* tunables */					\
	int q_batchlen;					\
	int q_max_queued;				\
	int q_max_flying;				\
	int q_max_jiffies;				\
	int q_max_contention;				\
	int q_over_pressure;				\
	int q_io_prio;					\
	bool q_ordering;				\


#define QUEUE_FUNCTIONS(PREFIX,ELEM_TYPE,HEAD,KEYFN,KEYCMP,HEAPTYPE)	\
									\
static inline							        \
void q_##PREFIX##_init(struct PREFIX##_queue *q)			\
{									\
	INIT_LIST_HEAD(&q->q_anchor);					\
	q->heap_low = NULL;						\
	q->heap_high = NULL;						\
	spin_lock_init(&q->q_lock);					\
	atomic_set(&q->q_queued, 0);					\
	atomic_set(&q->q_flying, 0);					\
}									\
									\
static inline							        \
void q_##PREFIX##_insert(struct PREFIX##_queue *q, ELEM_TYPE *elem)	\
{									\
	unsigned long flags;						\
									\
	traced_lock(&q->q_lock, flags);					\
									\
	if (q->q_ordering) {						\
		struct pairing_heap_##HEAPTYPE **use = &q->heap_high;	\
		if (KEYCMP(KEYFN(elem), &q->heap_margin) <= 0) {		\
			use = &q->heap_low;				\
		}							\
		ph_insert_##HEAPTYPE(use, &elem->ph);			\
	} else {							\
		list_add_tail(&elem->HEAD, &q->q_anchor);		\
	}								\
	atomic_inc(&q->q_queued);					\
	atomic_inc(&q->q_total);					\
	q->q_last_insert = jiffies;					\
									\
	traced_unlock(&q->q_lock, flags);				\
}									\
									\
static inline							        \
void q_##PREFIX##_pushback(struct PREFIX##_queue *q, ELEM_TYPE *elem)	\
{									\
	unsigned long flags;						\
									\
	if (q->q_ordering) {						\
		atomic_dec(&q->q_total);				\
		q_##PREFIX##_insert(q, elem);				\
		return;							\
	}								\
									\
	traced_lock(&q->q_lock, flags);					\
									\
	list_add(&elem->HEAD, &q->q_anchor);				\
	atomic_inc(&q->q_queued);					\
									\
	traced_unlock(&q->q_lock, flags);				\
}									\
									\
static inline							        \
ELEM_TYPE *q_##PREFIX##_fetch(struct PREFIX##_queue *q)			\
{									\
	ELEM_TYPE *elem = NULL;						\
	unsigned long flags;						\
									\
	traced_lock(&q->q_lock, flags);					\
									\
	if (q->q_ordering) {						\
		if (!q->heap_high) {					\
			q->heap_high = q->heap_low;			\
			q->heap_low = NULL;				\
			q->heap_margin = 0;				\
			q->last_pos = 0;				\
		}							\
		if (q->heap_high) {					\
			elem = container_of(q->heap_high, ELEM_TYPE, ph); \
									\
			if (unlikely(KEYCMP(KEYFN(elem), &q->last_pos) < 0)) { \
				MARS_ERR("backskip pos %lld -> %lld\n", q->last_pos, KEYFN(elem)); \
			}						\
			memcpy(&q->last_pos, KEYFN(elem), sizeof(q->last_pos));	\
									\
			if (KEYCMP(KEYFN(elem), &q->heap_margin) > 0) {	\
				memcpy(&q->heap_margin, KEYFN(elem), sizeof(q->heap_margin)); \
			}						\
			ph_delete_min_##HEAPTYPE(&q->heap_high);	\
			atomic_dec(&q->q_queued);			\
		}							\
	} else if (!list_empty(&q->q_anchor)) {				\
		struct list_head *next = q->q_anchor.next;		\
		list_del_init(next);					\
		atomic_dec(&q->q_queued);				\
		elem = container_of(next, ELEM_TYPE, HEAD);		\
	}								\
									\
	traced_unlock(&q->q_lock, flags);				\
									\
	return elem;							\
}									\
									\
static inline							        \
bool q_##PREFIX##_is_ready(struct logger_queue *q)		        \
{									\
	struct PREFIX##_queue *dep;					\
	int queued = atomic_read(&q->q_queued);				\
	int contention;							\
	int max_contention;						\
	int over;							\
	int flying;							\
	bool res = false;						\
									\
	/* 1) when empty, there is nothing to do.			\
	 */								\
	if (queued <= 0)							\
		goto always_done;					\
									\
	/* compute some characteristic measures				\
	 */								\
	contention = 0;							\
	if (q->q_contention) {						\
		contention = atomic_read(q->q_contention);		\
	}								\
	dep = q->q_dep;							\
	while (dep) {							\
		contention += atomic_read(&dep->q_queued) + atomic_read(&dep->q_flying); \
		dep = dep->q_dep;					\
	}								\
	max_contention = q->q_max_contention;				\
	over = queued - q->q_max_queued;				\
	if (over > 0 && q->q_over_pressure > 0) {			\
		max_contention += over / q->q_over_pressure;		\
	}								\
									\
	/* 2) check whether queue is halted				\
	 */								\
	if (q->q_barrier && contention > 0)				\
		goto always_done;					\
									\
	/* 3) when other queues are too much contended,			\
	 * refrain from contending the IO system even more.		\
	 */								\
	if (contention > max_contention) {				\
		goto always_done;					\
	}								\
									\
	/* 4) when the maximum queue length is reached, start IO.	\
	 */								\
	res = true;							\
	if (over > 0)							\
		goto limit;						\
									\
	/* 5) also start IO when queued requests are too old		\
	 * (measured in realtime)					\
	 */								\
	if (q->q_max_jiffies > 0 &&					\
	   (long long)jiffies - q->q_last_insert >= q->q_max_jiffies)	\
		goto limit;						\
									\
	/* 6) when no contention, start draining the queue.		\
	 */								\
	if (contention <= 0)						\
		goto limit;						\
									\
	res = false;							\
	goto always_done;						\
									\
limit:									\
	/* Limit the number of flying requests (parallelism)		\
	 */								\
	flying = atomic_read(&q->q_flying);				\
	if (q->q_max_flying > 0 && flying >= q->q_max_flying)		\
		res = false;						\
									\
always_done:								\
	return res;							\
}									\

#endif
