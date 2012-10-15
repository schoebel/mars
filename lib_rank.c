// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
// (c) 2012 Thomas Schoebel-Theuer

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>

#include "mars.h"
#include "lib_rank.h"

void ranking_compute(struct rank_data *rkd, const struct rank_info rki[], int x)
{
	int i;

	for (i = 0; ; i++) {
		int x0 = rki[i].rki_x;
		int x1;
		int y0;
		int y1;
		int points;
		
		if (x0 == RKI_DUMMY)
			break;

		if (x < x0)
			continue;

		x1 = rki[i+1].rki_x;

		if (x1 == RKI_DUMMY)
			break;
		
		y0 = rki[i].rki_y;
		y1 = rki[i+1].rki_y;

		// linear interpolation
		points = ((long long)(x - x0) * (long long)(y1 - y0)) / (x1 - x0) + y0;
		MARS_IO("i = %d x0 = %d x1 = %d y0 = %d y1 = %d points = %d\n", i, x0, x1, y0, y1, points);
		rkd->rkd_tmp += points;
		break;
	}
}
EXPORT_SYMBOL_GPL(ranking_compute);

int ranking_select(struct rank_data rkd[], int rkd_count)
{
	int res = -1;
	int max = INT_MIN / 2;
	int i;

	MARS_IO("rkd_count = %d\n", rkd_count);

	for (i = 0; i < rkd_count; i++) {
		struct rank_data *tmp = &rkd[i];
		int rest = tmp->rkd_current_points;
		if (rest <= 0)
			continue;
		//rest -= tmp->rkd_got;
		if (rest > max) {
			max = rest;
			res = i;
		}
	}
	/* Prevent underflow in the long term
	 * and reset the "clocks" after each round of
	 * weighted round-robin selection.
	 */
	if (max < 0 && res >= 0) {
		for (i = 0; i < rkd_count; i++)
			rkd[i].rkd_got += max;
	}
	MARS_IO("res = %d\n", res);
	return res;
}
EXPORT_SYMBOL_GPL(ranking_select);
