#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "memreq.h"
#include "malloc.h"

//#define DEBUG_ENABLE
#ifdef DEBUG_ENABLE
#define DEBUG_MSG \
	printf("\n%s",__func__);

#define DEBUG_TYPE_MSG(msg, val) do{\
	 printf(msg,val);\
}while(0);

#define DUMP_BLOCK_TABLE do{\
	m_block_t *blk;\
	blk=blk_head;\
	while(blk){\
		printf("\n Block %p, Size %lu",blk, blk->size);\
		if (blk->free == FALSE);\
		      printf("\n ASHU");\
		blk = blk->next;\
	}\
}while(0);
#else
#define DUMP_BLOCK_TABLE
#define DEBUG_TYPE_MSG(msg,val)
#define DEBUG_MSG
#endif


/* Random signature */
#define MYMALLOC 'a'

#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGE_ALIGN(size) ((size + (PAGESIZE -1)) & ~(PAGESIZE -1))

#define TRUE 1
#define FALSE 0
#define ALIGNMENT 8
#define ALIGN(size) ((size + (ALIGNMENT-1)) & ~(ALIGNMENT -1))
#define ALIGN_B_SIZE ALIGN(sizeof(m_block_t)) 

#define BLOCK_DATA(blk) (blk->data)

/* M Block Data Structure */
typedef struct m_block {
	size_t size;
    	uint32_t free;
	uint8_t mymalloc; /* Signature Matching */
	struct m_block* next;
	struct m_block* prev;
	char data[0];	/* Start of data */
}m_block_t;

/* Block Head */
void *blk_head = NULL;

static void inline split_block(m_block_t *blk, size_t size) {
	m_block_t *blk_new;
	
	blk_new = (m_block_t*) (BLOCK_DATA(blk) + size);
	blk_new->size = blk->size - size - ALIGN_B_SIZE;
	blk_new->next = blk->next;
	blk_new->prev = blk;
 	blk_new->free = TRUE;
 	
	blk->next = blk_new;
	blk->size  = size;
	if (blk_new->next)
		blk_new->next->prev = blk_new;
}

static  m_block_t* allocate_block_page(m_block_t *blk, size_t size) {
	
	m_block_t *blk_new;
	size_t pages_needed;
	pages_needed = PAGE_ALIGN(size + ALIGN_B_SIZE);
	/* Page align before calling get memory */
    	blk_new = (m_block_t*) get_memory(pages_needed);
	//blk_new = (m_block_t*) get_memory(size);
	if (NULL == blk_new) {
		return NULL;
	}
     	blk_new->size = pages_needed - ALIGN_B_SIZE;
	DEBUG_TYPE_MSG("Size %lu", blk_new->size);
	//blk_new->size = size;
	blk_new->next = NULL;
	blk_new->prev = blk;
	blk_new->free = TRUE;
	/* Last Element Append this page*/
	if (blk) {
		blk->next = blk_new;
	}	
   	if ((blk_new->size - size) >= (ALIGN_B_SIZE + ALIGNMENT)) {
     		split_block(blk_new, size);
    	}
	blk_new->free = FALSE;
	blk_new->mymalloc = MYMALLOC;
	return blk_new;
}

/* Add block */
static  m_block_t* add_block_node(size_t size) {
	m_block_t *blk = blk_head;
	m_block_t *blk_prev = NULL;
	/* Find First element in Block list */
	while (blk && !(blk->free && blk->size >= size)) {
		blk_prev = blk;
		blk = blk->next;
	}
	/* if found check whether we can split */
	if (blk) {
		/* If the space is enough for 1 bytes align data
		 * split the block.
		 */
		if ((blk->size - size) >= (ALIGN_B_SIZE + ALIGNMENT))
			split_block(blk, size);
		blk->free = FALSE;
		blk->mymalloc = MYMALLOC;
	} else {
		/* Allocate Block Page and append in the 
		 * block list
		 */
		blk = allocate_block_page(blk_prev, size);
	}
	return blk;
}

/* Add Head Block */
static inline m_block_t *add_block_head(size_t size ) {
 	return allocate_block_page(NULL, size);
}

/* First Fit Malloc Implemention */
void *malloc(size_t size) {
	
	DEBUG_TYPE_MSG("\nSize %lu", size);
	m_block_t *blk;
	if (size <= 0) return NULL;

	size = ALIGN(size);
	if (blk_head) {
		blk = add_block_node(size);
		if (NULL == blk)
			return NULL;
	} else {
		blk = add_block_head(size);
		if (NULL == blk)
			return NULL;
		blk_head = blk;
	}
	return (BLOCK_DATA(blk));
}

int valid_block(void *ptr);

static size_t highest(size_t in) {
    size_t num_bits = 0;

    while (in != 0) {
        ++num_bits;
        in >>= 1;
    }

    return num_bits;
}

void* calloc(size_t number, size_t size) {
    size_t number_size = 0;
  
    /* This prevents an integer overflow.  A size_t is a typedef to an integer
     * large enough to index all of memory.  If we cannot fit in a size_t, then
     * we need to fail.
     */
    if (highest(number) + highest(size) > sizeof(size_t) * CHAR_BIT) {
        errno = ENOMEM;
        return NULL;
    }

	
    number_size = number * size;
    void* ret = malloc(number_size);

    if (ret) {
        memset(ret, 0, number_size);
    }

    return ret;
}

void* realloc(void *ptr, size_t size) {

     if (NULL == ptr)
	return NULL;
     if(!valid_block(ptr))
	return NULL;
    size_t old_size = 0; /* XXX Set this to the size of the buffer pointed to by ptr */
      m_block_t* blk;
      blk = (m_block_t *)((char*)ptr - ALIGN_B_SIZE);	
      old_size = blk->size;
      void* ret = malloc(size);

    if (ret) {
        if (ptr) {
            memmove(ret, ptr, old_size < size ? old_size : size);
            free(ptr);
        }

        return ret;
    } else {
        errno = ENOMEM;
        return NULL;
    }
}


int valid_block(void *ptr) {
	m_block_t* blk;
	if (blk_head) {
		/* Within the range */
		if (ptr > blk_head && ptr < sbrk(0)) {
			blk = (m_block_t *)((char*)ptr - ALIGN_B_SIZE);
	 		return (MYMALLOC == blk->mymalloc);
		}

	}
	return 0;
}
/* Merge Block */
inline static m_block_t* merge_block(m_block_t* blk) {
	if(blk->next && blk->next->free) {
		blk->size += ALIGN_B_SIZE + blk->next->size;
		blk->next = blk->next->next;
		if (blk->next)
			blk->next->prev = blk;
	}
	return blk;
}

/* Add Head Block */
void free(void* ptr) {

	if(NULL == ptr)
		return;

	if (valid_block(ptr)) {
		m_block_t* blk;
		blk = (m_block_t *)((char*)ptr - ALIGN_B_SIZE);	
		blk->free = TRUE;
		
		if(blk->prev && blk->prev->free)  {
		     blk = merge_block(blk->prev);
		}

		if(blk->next) {
	 	       merge_block(blk);
		} else {
		// Free ?
		}
 	}
}


