// (c) 2012 Thomas Schoebel-Theuer / 1&1 Internet AG

#include "lib_timing.h"

#include <linux/kernel.h>
#include <linux/module.h>

#ifdef CONFIG_MARS_DEBUG

int report_timing(struct timing_stats *tim, char *str, int maxlen)
{
	int len = 0;
	int time = 1;
	int resol = 1;
	static const char *units[] = {
		"us",
		"ms",
		"s",
		"ERROR"
	};
	const char *unit = units[0];
	int unit_index = 0;
	int i;

	for (i = 0; i < TIMING_MAX; i++) {
		int this_len = snprintf(str, maxlen, "<%d%s = %d (%lld) ", resol, unit, tim->tim_count[i], (long long)tim->tim_count[i] * time);
		str += this_len;
		len += this_len;
		maxlen -= this_len;
		if (maxlen <= 1)
			break;
		resol <<= 1;
		time <<= 1;
		if (resol >= 1000) {
			resol = 1;
			unit = units[++unit_index];
		}
	}
	return len;
}
EXPORT_SYMBOL_GPL(report_timing);

#endif
