#include "text.h"
#include "sys.h"

static void put_u64(uint64_t v) {
    char tmp[24];
    uint32_t i = 0;
    if (v == 0) { uputc('0'); return; }
    while (v && i < (uint32_t)sizeof(tmp)) { tmp[i++] = (char)('0' + (v % 10u)); v /= 10u; }
    while (i) uputc(tmp[--i]);
}

void _start(void) {
    struct btext_manager mgr;
    struct btext_benchmark_result r;
    char date[32];
    btext_manager_init(&mgr);
    btext_benchmark(&mgr, &r, 64);
    (void)btext_format_datetime(1771718400ull, date, sizeof(date));
    uputs("textbench: glyphs="); put_u64(r.glyphs);
    uputs(" hits="); put_u64(r.cache_hits);
    uputs(" misses="); put_u64(r.cache_misses);
    uputs(" evictions="); put_u64(r.cache_evictions);
    uputs(" checksum="); put_u64(r.checksum);
    uputs(" date="); uputs(date);
    uputs("\n");
    sys_exit(0);
}
