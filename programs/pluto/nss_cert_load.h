#ifndef _NSS_CERT_LOAD_H
#define _NSS_CERT_LOAD_H

#include <libreswan.h>
extern bool load_coded_file(const char *filename, const char *type, chunk_t *blob);
extern bool cert_exists_in_nss(const char *nickname);
extern bool load_nss_cert_from_db(const char *nickname, cert_t *cert);
#endif /* _NSS_CERT_LOAD_H */
