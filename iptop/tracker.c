#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "tracker.h"

/*
 * keep a backward looking event record of x uri's
 * (uniquely) associated with counts of each one
 * use a constant time algorithm to maintain a top-Y
 * list. the idea here is that x is long enough for
 * the true top sites to tick often enough that their
 * entry does not fall out of the hash table.
 * intended for use with x >>>> y
 *
 */

static void uri_init(uri_t *uri) { utstring_init(&uri->uri); }
static void uri_fini(uri_t *uri) { utstring_done(&uri->uri); }

tracker_t *tracker_new(int cache_sz, int top_sz) {
  int i;
  tracker_t *t = calloc(1,sizeof(tracker_t));
  if (!t) return NULL;
  t->uri_cache = malloc(cache_sz * sizeof(uri_t));
  if (!t->uri_cache) {free(t); return NULL;}
  t->cache_sz = cache_sz;
  t->top_sz = top_sz;
  t->free_uri = t->uri_cache;
  t->free_count = t->cache_sz;
  for(i=0; i<t->cache_sz; i++) uri_init(&t->uri_cache[i]);
  utarray_init(&t->top,&ut_ptr_icd);
  return t;
}

// sort uri's by count. if count is equal sort old-to-new
static int topsort_low_to_high(const void *_a, const void *_b) { 
  uri_t **a = (uri_t**)_a;
  uri_t **b = (uri_t**)_b;
  int c = ((*a)->count - (*b)->count);
  if (c) return c;
  return (*a)->last - (*b)->last;
}

static int is_top(tracker_t *t, uri_t *u) {
  size_t l = utarray_len(&t->top);
  if (l < t->top_sz) return 1;
  uri_t **f = (uri_t**)utarray_front(&t->top);
  if (u->count >= (*f)->count) return 1;
  return 0;
}

static uri_t **lfind_in_top(tracker_t *t, uri_t *u) {
  uri_t **up=NULL;
  while( (up=(uri_t**)utarray_next(&t->top,up))) {
    if (u == *up) return up;
  }
  return NULL;
}

void tracker_hit(tracker_t *t, char *uri, time_t when, unsigned long amount) {
  uri_t *u;
  HASH_FIND(hh, t->head, uri, strlen(uri), u);
  if (!u) {
    // delete oldest one if at max 
    if (HASH_COUNT(t->head) == t->cache_sz) {
      uri_t *oldest = t->head;
      HASH_DELETE(hh, t->head, oldest);
      t->free_uri = oldest;
      t->free_count=1;
      if (is_top(t,oldest)) { // if it was in top list, clear record
        uri_t **p = lfind_in_top(t,oldest);
        if (p) utarray_erase(&t->top,utarray_eltidx(&t->top,p),1);
      }
    }
    // claim first free slot
    u = t->free_uri; assert(u);
    t->free_uri = (--t->free_count) ? (t->free_uri+1) : NULL;
    utstring_clear(&u->uri);
    utstring_bincpy(&u->uri, uri, strlen(uri));
    u->count=0;
    u->last=0;
  } else {
    HASH_DELETE(hh, t->head, u); // before promoting to newest 
  }
  char *uri_ptr = utstring_body(&u->uri);
  int uri_len = utstring_len(&u->uri);
  HASH_ADD_KEYPTR(hh, t->head, uri_ptr, uri_len, u); //newest
  u->count += amount;
  if (when > u->last) u->last=when;
  if (is_top(t,u)) { // maintain top list
    // may have higher-count items in t->uri_cache but 
    // to avoid rescanning we'll insert this one. let
    // statistics keep top good as long as cache_sz is
    // long enough so true top sites don't roll off 
    // between their periodic events coming in
    if (!lfind_in_top(t,u)) utarray_push_back(&t->top,&u);
    utarray_sort(&t->top,topsort_low_to_high);
    if (utarray_len(&t->top) > t->top_sz) utarray_erase(&t->top,0,1);
  }
}

void show_tracker(tracker_t *t) {
  uri_t *u, *tmp;
  HASH_ITER(hh, t->head, u, tmp) {
    printf(" %s: %lu\n",  utstring_body(&u->uri), u->count);
  }
  printf("\n");
}

void show_tracker_top(tracker_t *t) {
  uri_t **up=NULL,*u;
  while( (up=(uri_t**)utarray_next(&t->top,up))) {
    u = *up;
    printf(" top> %s: %lu\n",  utstring_body(&u->uri), u->count);
  }
  printf("\n");
}

void tracker_free(tracker_t *t) {
  int i;
  HASH_CLEAR(hh,t->head);
  for(i=0; i<t->cache_sz; i++) uri_fini(&t->uri_cache[i]);
  free(t->uri_cache);
  utarray_done(&t->top);
  free(t);
}
