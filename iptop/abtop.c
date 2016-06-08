#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "abtop.h"

/*
 * keep a backward looking event record of x id's associated with
 * bidirectional counts (ab, ba) associated to id.
 *
 * use a constant time algorithm to maintain a top list. the idea here is that
 * x is long enough for the true top ids to have contributing events (ab, or
 * ba) often enough that the ab (canonicalized) entry does not fall out of the
 * hash table.  
 *
 * In other words, ab or ba must occur among the last N distinct events
 * where N is the cache_sz or it gets ejected from the cache even though
 * the ab/ba count may be larger than others that remain in the cache.
 *
 */

static void ab_init(ab_t *ab) { utstring_init(&ab->id); }
static void ab_fini(ab_t *ab) { utstring_done(&ab->id); }

abtop_t *abtop_new(int cache_sz, int top_sz) {
  int i;
  abtop_t *t = calloc(1,sizeof(abtop_t));
  if (!t) return NULL;
  t->cache = malloc(cache_sz * sizeof(ab_t));
  if (!t->cache) {free(t); return NULL;}
  t->cache_sz = cache_sz;
  t->top_sz = top_sz;
  t->avail = t->cache;
  t->navail = t->cache_sz;
  for(i=0; i<t->cache_sz; i++) ab_init(&t->cache[i]);
  utarray_init(&t->top,&ut_ptr_icd);
  return t;
}

// sort id's by count. if count is equal sort old-to-new
static int topsort_low_to_high(const void *_a, const void *_b) { 
  ab_t **a = (ab_t**)_a;
  ab_t **b = (ab_t**)_b;
  int c = ((*a)->count - (*b)->count);
  if (c) return c;
  return (*a)->last - (*b)->last;
}

static int is_top(abtop_t *t, ab_t *u) {
  size_t l = utarray_len(&t->top);
  if (l < t->top_sz) return 1;
  ab_t **f = (ab_t**)utarray_front(&t->top);
  if (u->count >= (*f)->count) return 1;
  return 0;
}

static ab_t **lfind_in_top(abtop_t *t, ab_t *u) {
  ab_t **up=NULL;
  while( (up=(ab_t**)utarray_next(&t->top,up))) {
    if (u == *up) return up;
  }
  return NULL;
}

void abtop_hit(abtop_t *t, char *id, time_t when, unsigned long ab, unsigned long ba) {
  ab_t *u;
  HASH_FIND(hh, t->head, id, strlen(id), u);
  if (!u) {
    // delete oldest one if at max 
    if (HASH_COUNT(t->head) == t->cache_sz) {
      ab_t *oldest = t->head;
      HASH_DELETE(hh, t->head, oldest);
      t->avail = oldest;
      t->navail=1;
      if (is_top(t,oldest)) { // if it was in top list, clear record
        ab_t **p = lfind_in_top(t,oldest);
        if (p) utarray_erase(&t->top,utarray_eltidx(&t->top,p),1);
      }
    }
    // claim first free slot
    u = t->avail; assert(u);
    t->avail = (--t->navail) ? (t->avail+1) : NULL;
    utstring_clear(&u->id);
    utstring_bincpy(&u->id, id, strlen(id));
    u->count=0;
    u->ab=0;
    u->ba=0;
    u->last=0;
  } else {
    HASH_DELETE(hh, t->head, u); // before promoting to newest 
  }
  char *id_ptr = utstring_body(&u->id);
  int id_len = utstring_len(&u->id);
  HASH_ADD_KEYPTR(hh, t->head, id_ptr, id_len, u); //newest
  u->count += (ab + ba);
  u->ab += ab;
  u->ba += ba;
  if (when > u->last) u->last=when;
  if (is_top(t,u)) { // maintain top list
    if (!lfind_in_top(t,u)) utarray_push_back(&t->top,&u);
    utarray_sort(&t->top,topsort_low_to_high);
    if (utarray_len(&t->top) > t->top_sz) utarray_erase(&t->top,0,1);
  }
}

void show_abtop(abtop_t *t) {
  ab_t *u, *tmp;
  HASH_ITER(hh, t->head, u, tmp) {
    printf(" %s: %lu\n",  utstring_body(&u->id), u->count);
  }
  printf("\n");
}

void show_abtop_top(abtop_t *t) {
  ab_t **up=NULL,*u;
  while( (up=(ab_t**)utarray_next(&t->top,up))) {
    u = *up;
    printf(" top> %s: %lu\n",  utstring_body(&u->id), u->count);
  }
  printf("\n");
}

void abtop_free(abtop_t *t) {
  int i;
  HASH_CLEAR(hh,t->head);
  for(i=0; i<t->cache_sz; i++) ab_fini(&t->cache[i]);
  free(t->cache);
  utarray_done(&t->top);
  free(t);
}
