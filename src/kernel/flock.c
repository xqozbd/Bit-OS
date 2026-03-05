#include "kernel/flock.h"

#include "kernel/heap.h"
#include "kernel/spinlock.h"
#include "kernel/waitq.h"

struct flock_holder {
    uint32_t pid;
    uint32_t count;
    struct flock_holder *next;
};

struct file_lock {
    int node;
    uint32_t ex_pid;
    uint32_t ex_count;
    uint32_t sh_total;
    struct flock_holder *sh;
    spinlock_t lock;
    struct waitq wait;
    struct file_lock *next;
};

static spinlock_t g_flock_lock = {0};
static struct file_lock *g_flocks = NULL;

static struct file_lock *flock_find(int node) {
    struct file_lock *cur = g_flocks;
    while (cur) {
        if (cur->node == node) return cur;
        cur = cur->next;
    }
    return NULL;
}

static struct file_lock *flock_get(int node) {
    spinlock_lock(&g_flock_lock);
    struct file_lock *lock = flock_find(node);
    if (lock) {
        spinlock_unlock(&g_flock_lock);
        return lock;
    }
    lock = (struct file_lock *)kmalloc(sizeof(*lock));
    if (!lock) {
        spinlock_unlock(&g_flock_lock);
        return NULL;
    }
    lock->node = node;
    lock->ex_pid = 0;
    lock->ex_count = 0;
    lock->sh_total = 0;
    lock->sh = NULL;
    spinlock_init(&lock->lock);
    waitq_init(&lock->wait);
    lock->next = g_flocks;
    g_flocks = lock;
    spinlock_unlock(&g_flock_lock);
    return lock;
}

static struct flock_holder *holder_find(struct flock_holder *h, uint32_t pid) {
    while (h) {
        if (h->pid == pid) return h;
        h = h->next;
    }
    return NULL;
}

int flock_lock(int node, uint32_t pid, int mode, int nonblock) {
    struct file_lock *lock = flock_get(node);
    if (!lock) return -1;
    int want_ex = (mode & 2) != 0;
    int want_sh = (mode & 1) != 0;
    if (!want_ex && !want_sh) return -1;

    spinlock_lock(&lock->lock);
    for (;;) {
        if (want_ex) {
            if (lock->ex_pid == pid) {
                lock->ex_count++;
                spinlock_unlock(&lock->lock);
                return 0;
            }
            if (lock->ex_pid == 0 && lock->sh_total == 0) {
                lock->ex_pid = pid;
                lock->ex_count = 1;
                spinlock_unlock(&lock->lock);
                return 0;
            }
        } else if (want_sh) {
            if (lock->ex_pid == 0 || lock->ex_pid == pid) {
                struct flock_holder *h = holder_find(lock->sh, pid);
                if (!h) {
                    h = (struct flock_holder *)kmalloc(sizeof(*h));
                    if (!h) {
                        spinlock_unlock(&lock->lock);
                        return -1;
                    }
                    h->pid = pid;
                    h->count = 0;
                    h->next = lock->sh;
                    lock->sh = h;
                }
                h->count++;
                lock->sh_total++;
                spinlock_unlock(&lock->lock);
                return 0;
            }
        }
        if (nonblock) {
            spinlock_unlock(&lock->lock);
            return -2;
        }
        waitq_sleep(&lock->wait, &lock->lock);
    }
}

int flock_unlock(int node, uint32_t pid, int mode, uint32_t count) {
    struct file_lock *lock = flock_get(node);
    if (!lock || count == 0) return -1;
    int is_ex = (mode & 2) != 0;
    int is_sh = (mode & 1) != 0;
    spinlock_lock(&lock->lock);
    if (is_ex) {
        if (lock->ex_pid != pid || lock->ex_count == 0) {
            spinlock_unlock(&lock->lock);
            return -1;
        }
        if (count >= lock->ex_count) {
            lock->ex_count = 0;
            lock->ex_pid = 0;
        } else {
            lock->ex_count -= count;
        }
        if (lock->ex_pid == 0) waitq_wake_all(&lock->wait);
        spinlock_unlock(&lock->lock);
        return 0;
    }
    if (is_sh) {
        struct flock_holder *prev = NULL;
        struct flock_holder *h = lock->sh;
        while (h) {
            if (h->pid == pid) break;
            prev = h;
            h = h->next;
        }
        if (!h || h->count == 0) {
            spinlock_unlock(&lock->lock);
            return -1;
        }
        if (count >= h->count) {
            lock->sh_total -= h->count;
            if (prev) prev->next = h->next;
            else lock->sh = h->next;
            kfree(h);
        } else {
            h->count -= count;
            lock->sh_total -= count;
        }
        if (lock->sh_total == 0 && lock->ex_pid == 0) {
            waitq_wake_all(&lock->wait);
        }
        spinlock_unlock(&lock->lock);
        return 0;
    }
    spinlock_unlock(&lock->lock);
    return -1;
}

void flock_release_pid(uint32_t pid) {
    spinlock_lock(&g_flock_lock);
    struct file_lock *cur = g_flocks;
    while (cur) {
        spinlock_lock(&cur->lock);
        if (cur->ex_pid == pid) {
            cur->ex_pid = 0;
            cur->ex_count = 0;
        }
        struct flock_holder *prev = NULL;
        struct flock_holder *h = cur->sh;
        while (h) {
            struct flock_holder *next = h->next;
            if (h->pid == pid) {
                cur->sh_total -= h->count;
                if (prev) prev->next = next;
                else cur->sh = next;
                kfree(h);
            } else {
                prev = h;
            }
            h = next;
        }
        if (cur->ex_pid == 0 && cur->sh_total == 0) {
            waitq_wake_all(&cur->wait);
        }
        spinlock_unlock(&cur->lock);
        cur = cur->next;
    }
    spinlock_unlock(&g_flock_lock);
}
