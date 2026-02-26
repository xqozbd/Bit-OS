#ifndef USBMGR_H
#define USBMGR_H

int usbmgr_init(void);
int usbmgr_is_ready(void);
void usbmgr_poll(void);
int usbmgr_shutdown(void);

#endif /* USBMGR_H */
