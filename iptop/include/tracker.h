#include <time.h>
#include "utstring.h"
#include "utarray.h"
#include "uthash.h"

/* tracker for top X sites in last Y requests */

// this takes about 124 bytes per URI
// so to track 1M unique URI's takes about 118 mb
typedef struct {
  UT_string uri;
  time_t last;
  unsigned long count;
  UT_hash_handle hh;
} uri_t;

typedef struct {
  uri_t *head;
  uri_t *uri_cache;
  UT_array top;
  int cache_sz;  // Y
  int top_sz;    // X
  uri_t *free_uri;
  int free_count; // contiguous free slots starting at free_uri
} tracker_t;

tracker_t *tracker_new(int cache_sz, int top_sz);
void tracker_hit(tracker_t *t, char *uri, time_t when, unsigned long amount);
void tracker_free(tracker_t *t);
void show_tracker(tracker_t *t);
void show_tracker_top(tracker_t *t);
