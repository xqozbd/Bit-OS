#ifndef USER_DESKTOP_H
#define USER_DESKTOP_H

#include <stdint.h>

#define DESKTOP_PROTOCOL_VERSION 2u
#define DESKTOP_QUEUE_CAP 128u
#define DESKTOP_MAX_WINDOWS 8u
#define DESKTOP_TITLE_MAX 48u
#define DESKTOP_PATH_MAX 32u

#define DESKTOP_CAP_SHARED_BUFFERS (1u << 0)
#define DESKTOP_CAP_DAMAGE_TRACKING (1u << 1)
#define DESKTOP_CAP_POINTER_FOCUS (1u << 2)
#define DESKTOP_CAP_KEYBOARD_FOCUS (1u << 3)
#define DESKTOP_CAP_WINDOW_STATES (1u << 4)
#define DESKTOP_CAP_CONFIGURE_ACK (1u << 5)
#define DESKTOP_CAP_HEARTBEAT (1u << 6)
#define DESKTOP_CAP_RATE_LIMIT (1u << 7)

enum {
    DESKTOP_CMD_NOP = 0,
    DESKTOP_CMD_CREATE = 1,
    DESKTOP_CMD_DESTROY = 2,
    DESKTOP_CMD_MAP = 3,
    DESKTOP_CMD_UNMAP = 4,
    DESKTOP_CMD_MOVE = 5,
    DESKTOP_CMD_RESIZE = 6,
    DESKTOP_CMD_DAMAGE = 7,
    DESKTOP_CMD_FOCUS = 8,
    DESKTOP_CMD_CONFIGURE_ACK = 9,
    DESKTOP_CMD_SET_STATE = 10,
    DESKTOP_CMD_PING = 11,
    DESKTOP_CMD_PONG = 12
};

enum {
    DESKTOP_EVT_CREATED = 0x100u,
    DESKTOP_EVT_DESTROYED = 0x101u,
    DESKTOP_EVT_MAPPED = 0x102u,
    DESKTOP_EVT_UNMAPPED = 0x103u,
    DESKTOP_EVT_FOCUS = 0x104u,
    DESKTOP_EVT_POINTER_ENTER = 0x105u,
    DESKTOP_EVT_POINTER_LEAVE = 0x106u,
    DESKTOP_EVT_KEY = 0x107u,
    DESKTOP_EVT_POINTER = 0x108u,
    DESKTOP_EVT_CONFIGURE = 0x109u,
    DESKTOP_EVT_PING = 0x10Au,
    DESKTOP_EVT_RATE_LIMIT = 0x10Bu,
    DESKTOP_EVT_HUNG = 0x10Cu
};

enum {
    DESKTOP_WIN_STATE_MAPPED = 1u << 0,
    DESKTOP_WIN_STATE_ACTIVE = 1u << 1,
    DESKTOP_WIN_STATE_MAXIMIZED = 1u << 2,
    DESKTOP_WIN_STATE_FULLSCREEN = 1u << 3,
    DESKTOP_WIN_STATE_MINIMIZED = 1u << 4,
    DESKTOP_WIN_STATE_HUNG = 1u << 5,
    DESKTOP_WIN_STATE_THROTTLED = 1u << 6,
    DESKTOP_WIN_STATE_SERVER_OWNED = 1u << 7
};

struct desktop_msg {
    uint32_t cmd;
    uint32_t win_id;
    uint32_t serial;
    uint32_t flags;
    int32_t x;
    int32_t y;
    uint32_t w;
    uint32_t h;
    uint32_t arg0;
    uint32_t arg1;
    uint64_t timestamp_ns;
};

struct desktop_queue {
    uint32_t version;
    volatile uint32_t head;
    volatile uint32_t tail;
    volatile uint32_t dropped;
    uint32_t reserved;
    struct desktop_msg msgs[DESKTOP_QUEUE_CAP];
};

struct desktop_window_slot {
    uint32_t win_id;
    uint32_t owner_pid;
    uint32_t state;
    uint32_t z_order;
    int32_t x;
    int32_t y;
    uint32_t w;
    uint32_t h;
    uint32_t configure_serial;
    uint32_t heartbeat_ms;
    char title[DESKTOP_TITLE_MAX];
    char buffer_path[DESKTOP_PATH_MAX];
};

struct desktop_runtime {
    uint32_t version;
    uint32_t capabilities;
    uint32_t max_windows;
    uint32_t active_win_id;
    volatile uint32_t request_lock;
    uint32_t reserved0;
    struct desktop_queue requests;
    struct desktop_queue events;
    struct desktop_window_slot windows[DESKTOP_MAX_WINDOWS];
};

struct desktop_shm_window {
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t format;
    uint32_t flags;
    uint32_t configure_serial;
    int32_t damage_x;
    int32_t damage_y;
    uint32_t damage_w;
    uint32_t damage_h;
    uint64_t heartbeat_ns;
    uint64_t ack_serial;
    char title[DESKTOP_TITLE_MAX];
    struct desktop_queue events;
    uint32_t pixels[];
};

#endif /* USER_DESKTOP_H */
