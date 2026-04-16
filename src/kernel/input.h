#ifndef KERNEL_INPUT_H
#define KERNEL_INPUT_H

#include <stdint.h>

enum {
    INPUT_EVENT_KEY = 1,
    INPUT_EVENT_MOUSE = 2,
    INPUT_EVENT_DEVICE = 3
};

enum {
    INPUT_DEVICE_KEYBOARD = 1,
    INPUT_DEVICE_MOUSE = 2,
    INPUT_DEVICE_HOTPLUG = 3
};

enum {
    INPUT_MOD_SHIFT = 1u << 0,
    INPUT_MOD_CTRL  = 1u << 1,
    INPUT_MOD_ALT   = 1u << 2,
    INPUT_MOD_SUPER = 1u << 3
};

enum {
    INPUT_FLAG_PRESS    = 1u << 0,
    INPUT_FLAG_RELEASE  = 1u << 1,
    INPUT_FLAG_REPEAT   = 1u << 2,
    INPUT_FLAG_SECURE   = 1u << 3,
    INPUT_FLAG_SHORTCUT = 1u << 4
};

enum {
    INPUT_ACCEL_RAW = 0,
    INPUT_ACCEL_NORMAL = 1,
    INPUT_ACCEL_FAST = 2,
    INPUT_ACCEL_PRECISE = 3
};

enum {
    INPUT_IOCTL_GET_STATS = 0x4701u,
    INPUT_IOCTL_SET_SECURE = 0x4702u,
    INPUT_IOCTL_GET_SECURE = 0x4703u,
    INPUT_IOCTL_SET_KEYMAP = 0x4704u,
    INPUT_IOCTL_GET_KEYMAP = 0x4705u,
    INPUT_IOCTL_SET_ACCEL = 0x4706u,
    INPUT_IOCTL_GET_ACCEL = 0x4707u,
    INPUT_IOCTL_SET_CONFINEMENT = 0x4708u,
    INPUT_IOCTL_GET_CONFINEMENT = 0x4709u,
    INPUT_IOCTL_CLEAR_CONFINEMENT = 0x470Au,
    INPUT_IOCTL_REGISTER_SHORTCUT = 0x470Bu,
    INPUT_IOCTL_UNREGISTER_SHORTCUT = 0x470Cu
};

struct input_event {
    uint16_t type;
    uint16_t device;
    uint16_t code;
    uint16_t flags;
    uint32_t modifiers;
    uint64_t timestamp_ns;
    int32_t value;
    int32_t keycode;
    int32_t x;
    int32_t y;
    int32_t dx;
    int32_t dy;
    int32_t wheel_x;
    int32_t wheel_y;
    uint32_t buttons;
    uint32_t reserved;
};

struct input_stats {
    uint64_t total_events;
    uint64_t overflow_events;
    uint64_t reader_dropped_events;
    uint64_t reader_seq;
    uint32_t queue_capacity;
    uint32_t queue_depth;
    uint32_t secure_mode;
    uint32_t keymap;
    uint32_t accel_profile;
    uint32_t shortcut_count;
};

struct input_secure_request {
    uint32_t enabled;
    uint32_t reserved;
};

struct input_keymap_request {
    uint32_t layout;
    char name[8];
};

struct input_accel_request {
    uint32_t profile;
    uint32_t reserved;
};

struct input_confine_rect {
    int32_t x;
    int32_t y;
    int32_t w;
    int32_t h;
    uint32_t enabled;
    uint32_t reserved;
};

struct input_shortcut_request {
    uint32_t modifiers;
    uint32_t scancode;
    uint32_t keycode;
    uint32_t flags;
};

void input_init(void);
void input_push_key(uint16_t scancode, int pressed, int32_t keycode, uint32_t modifiers, int repeat);
void input_push_mouse(int32_t x, int32_t y, int32_t dx, int32_t dy,
                      int32_t wheel_x, int32_t wheel_y, uint32_t buttons);
void input_push_device(uint16_t device_code, int attached);
void input_filter_mouse_motion(int32_t *x, int32_t *y, int32_t *dx, int32_t *dy);

uint64_t input_current_seq(void);
uint32_t input_reader_open(void);
void input_reader_retain(uint32_t cookie);
void input_reader_close(uint32_t cookie);
int input_reader_pop(uint64_t *seq_io, uint64_t *dropped_io, uint32_t cookie, struct input_event *out);
int input_reader_has_event(uint64_t seq, uint32_t cookie);
void input_reader_fill_stats(uint64_t seq, uint64_t dropped, uint32_t cookie, struct input_stats *out);

int input_set_secure(uint32_t cookie, int enabled);
int input_get_secure(void);
int input_set_keymap(const struct input_keymap_request *req);
void input_get_keymap(struct input_keymap_request *out);
int input_set_accel_profile(uint32_t profile);
uint32_t input_get_accel_profile(void);
int input_set_confinement(uint32_t cookie, const struct input_confine_rect *rect);
void input_get_confinement(struct input_confine_rect *out);
void input_clear_confinement(uint32_t cookie);
int input_register_shortcut(uint32_t cookie, const struct input_shortcut_request *req);
int input_unregister_shortcut(uint32_t cookie, const struct input_shortcut_request *req);

#endif /* KERNEL_INPUT_H */
