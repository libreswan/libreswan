/* Process IKE_SA_INIT payload, for libreswan
 *
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
 */

#ifndef IKEV2_IKE_SA_INIT_H
#define IKEV2_IKE_SA_INIT_H

void process_v2_IKE_SA_INIT(struct msg_digest *md);

#endif
