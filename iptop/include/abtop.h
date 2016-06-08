#include <time.h>
#include "utstring.h"
#include "utarray.h"
#include "uthash.h"

/* A and B: entities interacting bidirectionally */

typedef struct {
  UT_string id;
  unsigned long ab;
  unsigned long ba;
  unsigned long count;
  time_t last;
  UT_hash_handle hh;
} ab_t;

typedef struct {
  ab_t *head;
  ab_t *cache;
  UT_array top;
  int cache_sz;  // Y
  int top_sz;    // X
  ab_t *avail;
  int navail; // contiguous free slots starting at avail
} abtop_t;

abtop_t *abtop_new(int cache_sz, int top_sz);
void abtop_hit(abtop_t *t, char *id, time_t when, unsigned long ab, unsigned long ba);
void abtop_free(abtop_t *t);
void show_abtop(abtop_t *t);
void show_abtop_top(abtop_t *t);
