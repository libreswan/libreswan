#ifndef CERT_REREAD_H
#define CERT_REREAD_H

struct fd;
struct whack_message;
struct connection;

extern void reread_cert(struct fd *whackfd, struct connection *c);

#endif /* CERT_REREAD_H */
