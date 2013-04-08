// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_PROC_H
#define MARS_PROC_H

typedef char * (*mars_info_fn)(void);

extern mars_info_fn mars_info;

/////////////////////////////////////////////////////////////////////////

// init

extern int init_mars_proc(void);
extern void exit_mars_proc(void);

#endif
