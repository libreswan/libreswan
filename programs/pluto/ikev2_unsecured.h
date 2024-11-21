/* Process UNSECURED payload, for libreswan
 *
 * Copyright (C) 2024  Andrew Cagney
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
 */

#ifndef IKEV2_UNSECURED_H
#define IKEV2_UNSECURED_H

struct msg_digest;

void process_v2_UNSECURED_message(struct msg_digest *md);

#endif
