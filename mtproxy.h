#ifndef MTPROXY_H
#define MTPROXY_H

#include "common.h"

struct MTProxyData;

int parse_mtproxy_header(const struct MTProxyData *mtproxy_data, const char *data, size_t data_len);

struct MTProxyData *new_mtproxy_data(const char **secrets, size_t secrets_len);

#define MTPROXY_MATCH   0
#define MTPROXY_UNMATCH 1

#define SECRET_LENGTH 16

#endif /* end of include guard */
