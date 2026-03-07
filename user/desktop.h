#ifndef USER_DESKTOP_H
#define USER_DESKTOP_H

#include <stdint.h>

#define DESKTOP_PROTOCOL_VERSION 1u
#define DESKTOP_QUEUE_CAP 64u

enum {
    DESKTOP_CMD_NOP = 0,
    DESKTOP_CMD_CREATE = 1,
    DESKTOP_CMD_MOVE = 2,
    DESKTOP_CMD_DAMAGE = 3,
    DESKTOP_CMD_CLOSE = 4
};

struct desktop_msg {
    uint32_t cmd;
    uint32_t win_id;
    int32_t x;
    int32_t y;
    uint32_t w;
    uint32_t h;
    uint32_t arg0;
    uint32_t arg1;
};

struct desktop_queue {
    uint32_t version;
    volatile uint32_t head;
    volatile uint32_t tail;
    struct desktop_msg msgs[DESKTOP_QUEUE_CAP];
};

struct desktop_shm_window {
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t format;
    uint32_t pixels[];
};

#endif /* USER_DESKTOP_H */
