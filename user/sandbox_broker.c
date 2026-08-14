#include "sys.h"

void _start(void) {
    struct sandbox_broker_request req;
    for (uint32_t i = 0; i < sizeof(req.target); ++i) req.target[i] = 0;
    for (uint32_t i = 0; i < sizeof(req.reason); ++i) req.reason[i] = 0;
    req.op = SANDBOX_BROKER_REGISTER;
    req.access = 0;
    if (sys_broker(&req) < 0) {
        uputs("sandbox-broker: register failed\n");
        sys_exit(1);
    }
    uputs("sandbox-broker: registered\n");
    for (;;) sys_sleep_ms(1000);
}
