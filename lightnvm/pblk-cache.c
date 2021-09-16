/*
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <javier@cnexlabs.com>
 *                  Matias Bjorling <matias@cnexlabs.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * pblk-cache.c - pblk's write cache
 */

#include "pblk.h"

int pblk_write_to_cache(struct pblk *pblk, struct bio *bio, unsigned long flags)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,15,0)
	struct request_queue *q = pblk->dev->q;
#endif
	struct pblk_w_ctx w_ctx;
	sector_t lba = pblk_get_lba(bio);
	unsigned long start_time = jiffies;
	unsigned int bpos, pos;
	int nr_entries = pblk_get_secs(bio);
	int i, ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
	generic_start_io_acct(WRITE, bio_sectors(bio), &pblk->disk->part0);
#else
	generic_start_io_acct(q, WRITE, bio_sectors(bio), &pblk->disk->part0);
#endif

	/* bookmark: Update the write buffer head (mem) with the entries that we can
	 * write. The write in itself cannot fail, so there is no need to
	 * rollback from here on.
	 */
retry:
	ret = pblk_rb_may_write_user(&pblk->rwb, bio, nr_entries, &bpos);
	switch (ret) {
	case NVM_IO_REQUEUE:
		io_schedule();
		goto retry;
	case NVM_IO_ERR:
		pblk_pipeline_stop(pblk);
		goto out;
	}

	pblk_ppa_set_empty(&w_ctx.ppa);
	w_ctx.flags = flags;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
	if (bio->bi_rw & REQ_FLUSH)
#else
	if (bio->bi_opf & REQ_PREFLUSH)
#endif
	{
		w_ctx.flags |= PBLK_FLUSH_ENTRY;
		pblk_write_kick(pblk);
	}

	if (unlikely(!bio_has_data(bio)))
		goto out;

	for (i = 0; i < nr_entries; i++) {
		void *data = bio_data(bio);
		w_ctx.lba = lba + i;

		pos = pblk_rb_wrap_pos(&pblk->rwb, bpos + i);
		//uint16_t *tmp = data+i*PAGE_SIZE;
		//printk("w: lba=0x%08llx, dat=0x%04x\n", w_ctx.lba, *tmp);
		pblk_rb_write_entry_user(&pblk->rwb, data, w_ctx, pos);
		bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
	}

	atomic64_add(nr_entries, &pblk->user_wa);

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(nr_entries, &pblk->inflight_writes);
	atomic_long_add(nr_entries, &pblk->req_writes);
#endif

	pblk_rl_inserted(&pblk->rl, nr_entries);

out:
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
	generic_end_io_acct(WRITE, &pblk->disk->part0, start_time);
#else
	generic_end_io_acct(q, WRITE, &pblk->disk->part0, start_time);
#endif
	pblk_write_should_kick(pblk);
	return ret;
}

/*
 * On GC the incoming lbas are not necessarily sequential. Also, some of the
 * lbas might not be valid entries, which are marked as empty by the GC thread
 */
//bookmark: when use SLC cache, gc write TLC first.
int pblk_write_gc_to_cache(struct pblk *pblk, struct pblk_gc_rq *gc_rq)
{
	struct pblk_w_ctx w_ctx;
	unsigned int bpos, pos;
	void *data;
	int i, valid_entries;

	/* Update the write buffer head (mem) with the entries that we can
	 * write. The write in itself cannot fail, so there is no need to
	 * rollback from here on.
	 */
retry:
	//printk("ocssd[%s]: secs_to_gc=%d, nr_entries=%d, line_id=%d\n", __func__, gc_rq->secs_to_gc, gc_rq->nr_secs, gc_rq->line->id);
	if (!pblk_rb_may_write_gc(&pblk->rwb, gc_rq->secs_to_gc, &bpos)) {
		io_schedule();
		goto retry;
	}

	w_ctx.flags = PBLK_IOTYPE_GC;
	pblk_ppa_set_empty(&w_ctx.ppa);

	for (i = 0, valid_entries = 0; i < gc_rq->nr_secs; i++) {
		if (gc_rq->lba_list[i] == ADDR_EMPTY)
			continue;

		w_ctx.lba = gc_rq->lba_list[i];

		pos = pblk_rb_wrap_pos(&pblk->rwb, bpos + valid_entries);

		data = gc_rq->data+i*PAGE_SIZE;
		pblk_rb_write_entry_gc(&pblk->rwb, data, w_ctx, gc_rq->line,
						gc_rq->paddr_list[i], pos);

		valid_entries++;
	}

	WARN_ONCE(gc_rq->secs_to_gc != valid_entries, "pblk: inconsistent GC write\n");

	atomic64_add(valid_entries, &pblk->gc_wa);

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(valid_entries, &pblk->inflight_writes);
	atomic_long_add(valid_entries, &pblk->recov_gc_writes);
#endif

	pblk_write_should_kick(pblk);
	return NVM_IO_OK;
}
