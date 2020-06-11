#ifndef CERT_ROTATION_H
#define CERT_ROTATION_H

struct fd;
struct whack_message;

extern void rotate_cert(struct fd *whackfd, const struct whack_message *wm);

#endif // CERT_ROTATION_H
