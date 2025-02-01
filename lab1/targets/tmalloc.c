 /*
 * Trivial malloc() implementation
 *
 * Inspired by K&R2 malloc() and Doug Lea malloc().
 */

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>


// Chunk header

typedef union {

	struct {

	      uint32_t l;       // leftward chunk
	      uint32_t r;       // rightward chunk + free bit (see below)
	};

	uint64_t align;		// Forces 64-bit alignment

} CHUNK;


// Store the freebit (1 if the chunk is free, 0 if it is busy)
// in the low-order bit of the chunk's r pointer.

#define SET_FREEBIT(chunk) ( (chunk)->r |= 0x1 )
#define CLR_FREEBIT(chunk) ( (chunk)->r &= ~0x1 )
#define GET_FREEBIT(chunk) ( (chunk)->r & 0x1 )

// It's only safe to operate on chunk->r if we know freebit
// is unset; otherwise, we use... 

#define RIGHT(chunk) ((CHUNK *)(~0x1 & (uint64_t)(chunk)->r))

// chunk size is implicit from l-r

#define CHUNKSIZE(chunk) ((uint64_t)RIGHT((chunk)) - (uint64_t)(chunk))

// back or forward chunk header

#define TOCHUNK(vp) (-1 + (CHUNK *)(vp))
#define FROMCHUNK(chunk) ((void *)(1 + (chunk)))

// For lab purposes, a static arena is good enough. Place it after
// some dummy bytes, to make the addresses friendlier for the lab
// assignment.

#define ARENA_CHUNKS (65536/sizeof(CHUNK))
static unsigned int dummy[5680000];
static CHUNK arena[ARENA_CHUNKS];

static CHUNK *bot = NULL;       // all free space, initially
static CHUNK *top = NULL;       // delimiter chunk for top of arena


static void
init(void)
{
	bot = &arena[0];
	top = &arena[ARENA_CHUNKS-1];

	bot->l = (uint32_t)(uint64_t)NULL;
	bot->r = (uint32_t)(uint64_t)top;
	SET_FREEBIT(bot);

	top->l = (uint32_t)(uint64_t)bot;
	top->r = (uint32_t)(uint64_t)NULL;
	CLR_FREEBIT(top);

	// To make the lab easier, mark the pages that contain our
	// 'arena' as read/write/execute
	
	void * vp = (void *) &arena;
	uint64_t pageAlign = (uint64_t)vp % getpagesize();
	vp -= pageAlign;
	int rc;
	rc = mprotect(vp, (ARENA_CHUNKS * sizeof(CHUNK)) + pageAlign,
			(PROT_READ|PROT_WRITE|PROT_EXEC));
	assert( rc == 0 );
}


void *
tmalloc(const size_t nbytes)
{
	CHUNK *		p;
	uint64_t	size;

	if (bot == NULL) init();

	size = sizeof(CHUNK) * ((nbytes+sizeof(CHUNK)-1)/sizeof(CHUNK) + 1);

	for (p = bot; p != NULL; p = RIGHT(p))
		if (GET_FREEBIT(p) && CHUNKSIZE(p) >= size) break;
	if (p == NULL) return NULL;

	CLR_FREEBIT(p);
	if (CHUNKSIZE(p) > size)      /* create a remainder chunk */
	{
		CHUNK * q = (CHUNK *)(size + (char *)p);
		CHUNK * pr = (CHUNK *)(uint64_t)p->r;;

		q->l = (uint32_t)(uint64_t)p;
		q->r = (uint32_t)(uint64_t)pr;

		p->r = (uint32_t)(uint64_t)q;
		pr->l = (uint32_t)(uint64_t)q;

		SET_FREEBIT(q);
	}

	return FROMCHUNK(p);
}


void
tfree(const void * vp)
{
	CHUNK *	p;
	CHUNK * q;

	if (vp == NULL) return;

	p = TOCHUNK(vp);
	CLR_FREEBIT(p);

	q = (CHUNK *)(uint64_t)p->l;

	if (q != NULL && GET_FREEBIT(q)) /* try to consolidate leftward */
	{
		CLR_FREEBIT(q);
		q->r = p->r; // q->r = RIGHT(p)
		((CHUNK *)(uint64_t)(p->r))->l = (uint32_t)(uint64_t)q; // RIGHT(p)->l = q
		SET_FREEBIT(q);
		p = q;
	}

	q = RIGHT(p);
	if (q != NULL && GET_FREEBIT(q)) /* try to consolidate rightward */
	{
		CLR_FREEBIT(q);
		p->r = q->r;
		((CHUNK *)(uint64_t)q->r)->l = (uint32_t)(uint64_t)p;
		SET_FREEBIT(q);
	}

	SET_FREEBIT(p);
}


void *
trealloc(const void *vp, const size_t newbytes)
{
	void *	newp = NULL;

	/* behavior on corner cases conforms to SUSv2 */
	if (vp == NULL) return tmalloc(newbytes);

	if (newbytes != 0)
	{
		CHUNK *		oldchunk;
		uint64_t	bytes;

		newp = tmalloc(newbytes);
		if ( newp == NULL ) return NULL;

		oldchunk = TOCHUNK(vp);
		bytes = CHUNKSIZE(oldchunk) - sizeof(CHUNK);
		if (bytes > newbytes) bytes = newbytes;
		memcpy(newp, vp, bytes);
	}

	tfree(vp);
	return newp;
}


void *
tcalloc(const unsigned nelem, const size_t elsize)
{
	size_t	nbytes = nelem * elsize;
	void *	vp = tmalloc(nbytes);

	if ( vp == NULL ) return NULL;
	memset(vp, '\0', nbytes);
	return vp;
}
