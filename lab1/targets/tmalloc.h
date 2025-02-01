 /*
 * Trivial malloc() implementation
 *
 * Inspired by K&R2 malloc() and Doug Lea malloc().
 */

void *	tmalloc(const size_t nbytes);
void	tfree(const void *vp);
void *	trealloc(const void *vp, const size_t newbytes);
void *	tcalloc(const unsigned nelem, const size_t elsize);
