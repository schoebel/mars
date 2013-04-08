// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef META_H
#define META_H


/////////////////////////////////////////////////////////////////////////

// metadata descriptions

/* The idea is to describe your C structures in such a way that
 * transfers to disk or over a network become self-describing.
 *
 * In essence, this is a kind of version-independent marshalling.
 *
 * Advantage:
 * When you extend your original C struct (and of course update the
 * corresponding meta structure), old data on disk (or network peers
 * running an old version of your program) will remain valid.
 * Upon read, newly added fields missing in the old version will be simply
 * not filled in and therefore remain zeroed (if you don't forget to
 * initially clear your structures via memset() / initializers / etc).
 * Note that this works only if you never rename or remove existing
 * fields; you should only add new ones.
 * [TODO: add macros for description of ignored / renamed fields to
 *  overcome this limitation]
 * You may increase the size of integers, for example from 32bit to 64bit
 * or even higher; sign extension will be automatically carried out
 * when necessary.
 * [TODO; NYI]
 * Also, you may change the order of fields, because the metadata interpreter
 * will check each field individually; field offsets are automatically
 * maintained.
 *
 * Disadvantage: this adds some (small) overhead.
 */

enum field_type {
	FIELD_DONE,
	FIELD_REF,
	FIELD_SUB,
	FIELD_STRING,
	FIELD_RAW,
	FIELD_INT,
	FIELD_UINT,
};

struct meta {
	//char  field_name[MAX_FIELD_LEN];
	char *field_name;
	int   field_type;
	int   field_size;
	int   field_offset;
	const struct meta *field_ref;
};

#define _META_INI(NAME,STRUCT,TYPE)					\
	.field_name = #NAME,						\
	.field_type = TYPE,					        \
	.field_size = sizeof(((STRUCT*)NULL)->NAME),		        \
	.field_offset = offsetof(STRUCT, NAME)			        \

#define META_INI(NAME,STRUCT,TYPE) { _META_INI(NAME,STRUCT,TYPE) }

#define _META_INI_REF(NAME,STRUCT,REF)					\
	.field_name = #NAME,						\
	.field_type = FIELD_REF,				        \
	.field_size = sizeof(*(((STRUCT*)NULL)->NAME)),		        \
	.field_offset = offsetof(STRUCT, NAME),			        \
	.field_ref = REF

#define META_INI_REF(NAME,STRUCT,REF) { _META_INI_REF(NAME,STRUCT,REF) }

#define _META_INI_SUB(NAME,STRUCT,SUB)					\
	.field_name = #NAME,						\
	.field_type = FIELD_SUB,				        \
	.field_size = sizeof(((STRUCT*)NULL)->NAME),		        \
	.field_offset = offsetof(STRUCT, NAME),			        \
	.field_ref = SUB

#define META_INI_SUB(NAME,STRUCT,SUB) { _META_INI_SUB(NAME,STRUCT,SUB) }

extern const struct meta *find_meta(const struct meta *meta, const char *field_name);
//extern void free_meta(void *data, const struct meta *meta);

#endif
