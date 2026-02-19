/* IKEv2 helper interface, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * This code was developed with the support of IXIA communications.
 */

#include "constants.h"		/* for stf_status */
#include "lswcdefs.h"		/* for UNUSED; */

#include "defs.h"		/* for so_serial_t */
#include "ikev2_helper.h"
#include "server_pool.h"
#include "state.h"
#include "demux.h"

struct task {
	stf_status status;
	struct msg_digest *md;		/* must-delref */
	struct ikev2_task *task;	/* must-cleanup */
	ikev2_helper_fn *helper;
	ikev2_resume_fn *resume;
	ikev2_cleanup_fn *cleanup;
};

static void ikev2_helper_computer(struct logger *logger,
				  struct task *task,
				  int thread_unused UNUSED)
{
	task->status = task->helper(task->task, task->md, logger);
}

static void ikev2_helper_cleanup(struct task **task,
				 struct logger *logger)
{
	(*task)->cleanup(&(*task)->task, logger);
	md_delref(&(*task)->md);
	pfreeany(*task);
}

static stf_status ikev2_helper_completed(struct state *task_sa,
					 struct msg_digest *md,
					 struct task *task)
{
	if (task->status != STF_OK) {
		return task->status;
	}

	return task->resume(pexpect_ike_sa(task_sa), md, task->task);
}

static const struct task_handler ikev2_task_handler = {
	.name = "ikev2 helper",
	.computer_fn = ikev2_helper_computer,
	.completed_cb = ikev2_helper_completed,
	.cleanup_cb = ikev2_helper_cleanup,
};

void submit_ikev2_task(struct ike_sa *ike,
		       struct msg_digest *md,
		       struct ikev2_task *task,
		       ikev2_helper_fn *helper,
		       ikev2_resume_fn *resume,
		       ikev2_cleanup_fn *cleanup,
		       where_t where)
{
	struct task server_task = {
		.md = md_addref(md),
		.task = task,
		.helper = helper,
		.resume = resume,
		.cleanup = cleanup,
	};

	submit_task(/*callback-sa*/&ike->sa,
		    /*task-sa*/&ike->sa,
		    /*md*/md,
		    /*detach_whack*/false,
		    clone_thing(server_task, "ikev2 task"),
		    &ikev2_task_handler, where);
}
