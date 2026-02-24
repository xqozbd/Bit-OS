#include "sys.h"

enum { MAX_USERS = 16 };

struct user_entry {
    char name[32];
    uint32_t uid;
    uint32_t gid;
};

static int read_line(char *out, int max) {
    int len = 0;
    while (len + 1 < max) {
        char c = 0;
        long n = sys_read(0, &c, 1);
        if (n <= 0) continue;
        if (c == '\r') continue;
        if (c == '\n') {
            out[len] = '\0';
            return len;
        }
        out[len++] = c;
    }
    out[len] = '\0';
    return len;
}

static int load_passwd(char *buf, int buf_len, struct user_entry *users, int max_users) {
    if (!buf || buf_len <= 1 || !users || max_users <= 0) return 0;
    int fd = (int)sys_open("/etc/passwd", O_RDONLY);
    if (fd < 0) {
        buf[0] = '\0';
        return 0;
    }
    long n = sys_read(fd, buf, (size_t)(buf_len - 1));
    sys_close(fd);
    if (n <= 0) {
        buf[0] = '\0';
        return 0;
    }
    buf[n] = '\0';

    int count = 0;
    char *p = buf;
    while (*p && count < max_users) {
        char *line = p;
        while (*p && *p != '\n') p++;
        if (*p == '\n') *p++ = '\0';
        if (!line[0] || line[0] == '#') continue;

        char *u = line;
        char *c1 = u;
        while (*c1 && *c1 != ':') c1++;
        if (*c1 != ':') continue;
        *c1++ = '\0';
        char *u_id = c1;
        char *c2 = u_id;
        while (*c2 && *c2 != ':') c2++;
        if (*c2 != ':') continue;
        *c2++ = '\0';
        char *g_id = c2;
        char *c3 = g_id;
        while (*c3 && *c3 != ':') c3++;
        *c3 = '\0';

        struct user_entry *e = &users[count++];
        int i = 0;
        for (; i + 1 < (int)sizeof(e->name) && u[i]; ++i) e->name[i] = u[i];
        e->name[i] = '\0';
        e->uid = (uint32_t)uatoi(u_id);
        e->gid = (uint32_t)uatoi(g_id);
    }
    return count;
}

static int parse_user(const char *user, uint32_t *uid, uint32_t *gid, struct user_entry *users, int count) {
    if (!user || !users || count <= 0) return 0;
    for (int i = 0; i < count; ++i) {
        if (ustrcmp(users[i].name, user) == 0) {
            if (uid) *uid = users[i].uid;
            if (gid) *gid = users[i].gid;
            return 1;
        }
    }
    return 0;
}

static uint32_t next_uid(struct user_entry *users, int count) {
    uint32_t max = 999;
    for (int i = 0; i < count; ++i) {
        if (users[i].uid >= 1000 && users[i].uid > max) max = users[i].uid;
    }
    return max + 1;
}

static int has_user(struct user_entry *users, int count, const char *name) {
    for (int i = 0; i < count; ++i) {
        if (ustrcmp(users[i].name, name) == 0) return 1;
    }
    return 0;
}

static int write_passwd(const char *data, int len) {
    int fd = (int)sys_open("/etc/passwd", O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) return 0;
    int written = 0;
    while (written < len) {
        long n = sys_write(fd, data + written, (size_t)(len - written));
        if (n <= 0) break;
        written += (int)n;
    }
    sys_close(fd);
    return (written == len);
}

static int create_user_flow(char *buf, int buf_len, struct user_entry *users, int max_users) {
    char name[32];
    for (;;) {
        uputs("new username: ");
        read_line(name, (int)sizeof(name));
        if (name[0] == '\0') {
            uputs("name cannot be empty\n");
            continue;
        }
        int bad = 0;
        for (int i = 0; name[i]; ++i) {
            if (name[i] == ':' || name[i] == '\n' || name[i] == '\r' || name[i] == ' ') {
                bad = 1;
                break;
            }
        }
        if (bad) {
            uputs("invalid characters in name\n");
            continue;
        }
        if (has_user(users, max_users, name)) {
            uputs("user already exists\n");
            continue;
        }
        break;
    }

    uint32_t uid = next_uid(users, max_users);
    uint32_t gid = uid;

    int len = 0;
    if (buf[0]) {
        while (buf[len] && len + 1 < buf_len) len++;
        if (len > 0 && buf[len - 1] != '\n' && len + 1 < buf_len) buf[len++] = '\n';
    } else {
        const char *root = "root:0:0\n";
        for (int i = 0; root[i] && len + 1 < buf_len; ++i) buf[len++] = root[i];
    }

    char line[64];
    int l = 0;
    for (int i = 0; name[i] && l + 1 < (int)sizeof(line); ++i) line[l++] = name[i];
    if (l + 1 < (int)sizeof(line)) line[l++] = ':';
    char tmp[16];
    int t = 0;
    uint32_t v = uid;
    if (v == 0) tmp[t++] = '0';
    while (v && t < (int)sizeof(tmp)) { tmp[t++] = (char)('0' + (v % 10)); v /= 10; }
    for (int i = t - 1; i >= 0 && l + 1 < (int)sizeof(line); --i) line[l++] = tmp[i];
    if (l + 1 < (int)sizeof(line)) line[l++] = ':';
    v = gid; t = 0;
    if (v == 0) tmp[t++] = '0';
    while (v && t < (int)sizeof(tmp)) { tmp[t++] = (char)('0' + (v % 10)); v /= 10; }
    for (int i = t - 1; i >= 0 && l + 1 < (int)sizeof(line); --i) line[l++] = tmp[i];
    if (l + 1 < (int)sizeof(line)) line[l++] = '\n';

    if (len + l >= buf_len) {
        uputs("passwd file too large\n");
        return 0;
    }
    for (int i = 0; i < l; ++i) buf[len++] = line[i];
    buf[len] = '\0';

    if (!write_passwd(buf, len)) {
        uputs("failed to update /etc/passwd\n");
        return 0;
    }
    uputs("user added\n");
    return 1;
}

void _start(void) {
    char passwd[1024];
    struct user_entry users[MAX_USERS];
    int count = load_passwd(passwd, (int)sizeof(passwd), users, MAX_USERS);

    if (count == 0) {
        uputs("No users found. Create one now? (y/n): ");
        char ans[8];
        read_line(ans, (int)sizeof(ans));
        if (ans[0] != 'y' && ans[0] != 'Y') sys_exit(1);
        if (!create_user_flow(passwd, (int)sizeof(passwd), users, MAX_USERS)) sys_exit(1);
        count = load_passwd(passwd, (int)sizeof(passwd), users, MAX_USERS);
        if (count == 0) sys_exit(1);
    }

    for (;;) {
        if (count >= 1) {
            uputs("1) login\n2) add user\nchoice: ");
            char choice[8];
            read_line(choice, (int)sizeof(choice));
            if (choice[0] == '2') {
                if (create_user_flow(passwd, (int)sizeof(passwd), users, MAX_USERS)) {
                    count = load_passwd(passwd, (int)sizeof(passwd), users, MAX_USERS);
                }
                continue;
            }
        }

        uputs("login: ");
        char user[32];
        read_line(user, (int)sizeof(user));

        uint32_t uid = 0, gid = 0;
        if (!parse_user(user, &uid, &gid, users, count)) {
            uputs("login: unknown user\n");
            continue;
        }
        sys_setgid(gid);
        sys_setuid(uid);

        char *argv[2] = { "/bin/sh", 0 };
        sys_execve("/bin/sh", 1, argv, 0);
        sys_exit(1);
    }
}
