#ifndef PARTITION_H
#define PARTITION_H

#include <stddef.h>
#include <stdint.h>

enum partition_scheme {
    PART_SCHEME_NONE = 0,
    PART_SCHEME_MBR = 1,
    PART_SCHEME_GPT = 2,
};

struct partition_info {
    enum partition_scheme scheme;
    uint32_t device_index;
    uint32_t part_index;
    uint64_t first_lba;
    uint64_t last_lba;
    uint64_t lba_count;
    uint32_t type;
    char name[36];
};

void partition_init(void);
size_t partition_count(void);
const struct partition_info *partition_get(size_t index);

#endif /* PARTITION_H */
