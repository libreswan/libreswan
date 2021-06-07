#ifndef CERT_REREAD_H
#define CERT_REREAD_H

struct logger;
struct connection;

extern void reread_cert_connections(struct logger *logger);

#endif /* CERT_REREAD_H */
