#ifndef SYS_JOURNAL_H
#define SYS_JOURNAL_H

#include <stdint.h>

/* Initialize journaling for the current root filesystem if supported. */
void journal_init(void);

/* Called by VFS before data-changing ops; offset==size for truncate. */
int journal_log_write(int vfs_node, uint64_t offset, const uint8_t *data, uint32_t len);
int journal_log_truncate(int vfs_node, uint64_t new_size);

/* Remove pending log after successful operation. */
void journal_clear(void);

/* Replay outstanding log entries (done inside journal_init). */
void journal_replay(void);

/* Returns non-zero if journaling is active. */
int journal_enabled(void);

/* True if journaling should track this node. */
int journal_can_log(int vfs_node);

#endif /* SYS_JOURNAL_H */
