/*
 * nvme-lightnvm.c - LightNVM NVMe device
 *
 * Copyright (C) 2014-2015 IT University of Copenhagen
 * Initial release: Matias Bjorling <mb@lightnvm.io>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
 */

#include "nvme.h"

#include <linux/nvme.h>
#include <linux/bitops.h>
#include "lightnvm.h"
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/sched/sysctl.h>
//#include <uapi/linux/lightnvm.h>
#include <linux/delay.h>

//#define ENABLE_ASYNC_META
#define NVME_IDENTIFY_DATA_SIZE 4096
#define NVME_QID_ANY -1

enum nvme_nvm_admin_opcode {
	nvme_nvm_admin_identity		= 0xe2,
	nvme_nvm_admin_get_bb_tbl	= 0xf2,
	nvme_nvm_admin_set_bb_tbl	= 0xf1,
};

enum nvme_nvm_log_page {
	NVME_NVM_LOG_REPORT_CHUNK	= 0xca,
};

struct nvme_nvm_ph_rw {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd2;
	__le64			metadata;
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__le16			length;
	__le16			control;
	__le32			dsmgmt;
	__le64			resv;
};

struct nvme_nvm_erase_blk {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__le16			length;
	__le16			control;
	__le32			dsmgmt;
	__le64			resv;
};

struct nvme_nvm_identity {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__u32			rsvd11[6];
};

struct nvme_nvm_getbbtbl {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__u64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__u32			rsvd4[4];
};

struct nvme_nvm_setbbtbl {
	__u8			opcode;
	__u8			flags;
	__u16			command_id;
	__le32			nsid;
	__le64			rsvd[2];
	__le64			prp1;
	__le64			prp2;
	__le64			spba;
	__le16			nlb;
	__u8			value;
	__u8			rsvd3;
	__u32			rsvd4[3];
};

struct nvme_nvm_command {
	union {
		struct nvme_common_command common;
		struct nvme_nvm_ph_rw ph_rw;
		struct nvme_nvm_erase_blk erase;
		struct nvme_nvm_identity identity;
		struct nvme_nvm_getbbtbl get_bb;
		struct nvme_nvm_setbbtbl set_bb;
	};
};

struct nvme_nvm_id12_grp {
	__u8			mtype;
	__u8			fmtype;
	__le16			res16;
	__u8			num_ch;
	__u8			num_lun;
	__u8			num_pln;
	__u8			rsvd1;
	__le16			num_chk;
	__le16			num_pg;
	__le16			fpg_sz;
	__le16			csecs;
	__le16			sos;
	__le16			rsvd2;
	__le32			trdt;
	__le32			trdm;
	__le32			tprt;
	__le32			tprm;
	__le32			tbet;
	__le32			tbem;
	__le32			mpos;
	__le32			mccap;
	__le16			cpar;
	__u8			reserved[906];
} __packed;

struct nvme_nvm_id12_addrf {
	__u8			ch_offset;
	__u8			ch_len;
	__u8			lun_offset;
	__u8			lun_len;
	__u8			pln_offset;
	__u8			pln_len;
	__u8			blk_offset;
	__u8			blk_len;
	__u8			pg_offset;
	__u8			pg_len;
	__u8			sec_offset;
	__u8			sec_len;
	__u8			res[4];
} __packed;

struct nvme_nvm_id12 {
	__u8			ver_id;
	__u8			vmnt;
	__u8			cgrps;
	__u8			res;
	__le32			cap;
	__le32			dom;
	struct nvme_nvm_id12_addrf ppaf;
	__u8			resv[228];
	struct nvme_nvm_id12_grp grp;
	__u8			resv2[2880];
} __packed;

struct nvme_nvm_bb_tbl {
	__u8	tblid[4];
	__le16	verid;
	__le16	revid;
	__le32	rvsd1;
	__le32	tblks;
	__le32	tfact;
	__le32	tgrown;
	__le32	tdresv;
	__le32	thresv;
	__le32	rsvd2[8];
	__u8	blk[0];
};

struct nvme_nvm_id20_addrf {
	__u8			grp_len;
	__u8			pu_len;
	__u8			chk_len;
	__u8			lba_len;
	__u8			resv[4];
};

struct nvme_nvm_id20 {
	__u8			mjr;
	__u8			mnr;
	__u8			resv[6];

	struct nvme_nvm_id20_addrf lbaf;

	__le32			mccap;
	__u8			resv2[12];

	__u8			wit;
	__u8			resv3[31];

	/* Geometry */
	__le16			num_grp;
	__le16			num_pu;
	__le32			num_chk;
	__le32			clba;
	__u8			resv4[52];

	/* Write data requirements */
	__le32			ws_min;
	__le32			ws_opt;
	__le32			mw_cunits;
	__le32			maxoc;
	__le32			maxocpu;
	__u8			resv5[44];

	/* Performance related metrics */
	__le32			trdt;
	__le32			trdm;
	__le32			twrt;
	__le32			twrm;
	__le32			tcrst;
	__le32			tcrsm;
	__u8			resv6[40];

	/* Reserved area */
	__u8			resv7[2816];

	/* Vendor specific */
	__u8			vs[1024];
};

struct nvme_nvm_chk_meta {
	__u8	state;
	__u8	type;
	__u8	wi;
	__u8	rsvd[5];
	__le64	slba;
	__le64	cnlb;
	__le64	wp;
};

static void nvme_nvm_set_addr_12(struct nvm_addrf_12 *dst,
				 struct nvme_nvm_id12_addrf *src)
{
	dst->ch_len = src->ch_len;
	dst->lun_len = src->lun_len;
	dst->blk_len = src->blk_len;
	dst->pg_len = src->pg_len;
	dst->pln_len = src->pln_len;
	dst->sec_len = src->sec_len;

	dst->ch_offset = src->ch_offset;
	dst->lun_offset = src->lun_offset;
	dst->blk_offset = src->blk_offset;
	dst->pg_offset = src->pg_offset;
	dst->pln_offset = src->pln_offset;
	dst->sec_offset = src->sec_offset;

	dst->ch_mask = ((1ULL << dst->ch_len) - 1) << dst->ch_offset;
	dst->lun_mask = ((1ULL << dst->lun_len) - 1) << dst->lun_offset;
	dst->blk_mask = ((1ULL << dst->blk_len) - 1) << dst->blk_offset;
	dst->pg_mask = ((1ULL << dst->pg_len) - 1) << dst->pg_offset;
	dst->pln_mask = ((1ULL << dst->pln_len) - 1) << dst->pln_offset;
	dst->sec_mask = ((1ULL << dst->sec_len) - 1) << dst->sec_offset;
}

static int nvme_nvm_setup_12(struct nvme_nvm_id12 *id,
			     struct nvm_geo *geo)
{
	struct nvme_nvm_id12_grp *src;
	int sec_per_pg, sec_per_pl, pg_per_blk;

	if (id->cgrps != 1)
		return -EINVAL;

	src = &id->grp;

	if (src->mtype != 0) {
		pr_err("nvm: memory type not supported\n");
		return -EINVAL;
	}

	/* 1.2 spec. only reports a single version id - unfold */
	geo->major_ver_id = id->ver_id;
	geo->minor_ver_id = 2;

	/* Set compacted version for upper layers */
	geo->version = NVM_OCSSD_SPEC_12;

	geo->num_ch = src->num_ch;
	geo->num_lun = src->num_lun;
	geo->all_luns = geo->num_ch * geo->num_lun;

	geo->num_chk = le16_to_cpu(src->num_chk);

	geo->csecs = le16_to_cpu(src->csecs);
	geo->sos = le16_to_cpu(src->sos);

	pg_per_blk = le16_to_cpu(src->num_pg);
	sec_per_pg = le16_to_cpu(src->fpg_sz) / geo->csecs;
	sec_per_pl = sec_per_pg * src->num_pln;
	//pg_per_blk = le16_to_cpu(src->num_pg)/3; //TODO slc par
	geo->clba = sec_per_pl * pg_per_blk;

	geo->all_chunks = geo->all_luns * geo->num_chk;
	geo->total_secs = geo->clba * geo->all_chunks;

	//geo->ws_opt = sec_per_pg*1; //TODO slc par
	geo->ws_opt = sec_per_pg*3;
	geo->ws_min = sec_per_pg;
	//geo->mw_cunits = geo->ws_opt << 3;	/* default to MLC safe values */

	/* Do not impose values for maximum number of open blocks as it is
	 * unspecified in 1.2. Users of 1.2 must be aware of this and eventually
	 * specify these values through a quirk if restrictions apply.
	 */
	geo->maxoc = geo->all_luns * geo->num_chk;
	geo->maxocpu = geo->num_chk;

	geo->mccap = le32_to_cpu(src->mccap);

	geo->trdt = le32_to_cpu(src->trdt);
	geo->trdm = le32_to_cpu(src->trdm);
	geo->tprt = le32_to_cpu(src->tprt);
	geo->tprm = le32_to_cpu(src->tprm);
	geo->tbet = le32_to_cpu(src->tbet);
	geo->tbem = le32_to_cpu(src->tbem);

	/* 1.2 compatibility */
	geo->vmnt = id->vmnt;
	geo->cap = le32_to_cpu(id->cap);
	geo->dom = le32_to_cpu(id->dom);

	geo->mtype = src->mtype;
	geo->fmtype = src->fmtype;

	geo->cpar = le16_to_cpu(src->cpar);
	geo->mpos = le32_to_cpu(src->mpos);

	geo->pln_mode = NVM_PLANE_SINGLE;

	if (geo->mpos & 0x020202) {
		geo->pln_mode = NVM_PLANE_DOUBLE;
		geo->ws_opt <<= 1;
		printk("ocssd[%s]: set NVM_PLANE_DOUBLE\n", __func__);
	} else if (geo->mpos & 0x040404) {
		geo->pln_mode = NVM_PLANE_QUAD;
		geo->ws_opt <<= 2;
		printk("ocssd[%s]: set NVM_PLANE_QUAD\n", __func__);
	}
	geo->mw_cunits = geo->ws_opt * 4;	/* default to TLC safe values */

	geo->num_pln = src->num_pln;
	geo->num_pg = le16_to_cpu(src->num_pg);
	geo->fpg_sz = le16_to_cpu(src->fpg_sz);

	printk("ocssd[%s]: ************************************\n", __func__);
	printk("ocssd[%s]: sec_per_pg=%d, mw_cunits(cache)=%d, all_luns=%d\n", __func__, sec_per_pg, geo->mw_cunits, geo->all_luns);
	printk("ocssd[%s]: ws_min=%d, ws_opt=%d\n", __func__, geo->ws_min, geo->ws_opt);
	printk("ocssd[%s]: csecs(sector_size)=%d\n", __func__, geo->csecs);
	printk("ocssd[%s]: sos(out-of-band area size)=%d\n", __func__, geo->sos);
	printk("ocssd[%s]: clba(sectors per chunk)=%d =%dx%dx%d\n", __func__, geo->clba, pg_per_blk, sec_per_pg, src->num_pln);
	printk("ocssd[%s]: ************************************\n", __func__);
	nvme_nvm_set_addr_12((struct nvm_addrf_12 *)&geo->addrf, &id->ppaf);

	return 0;
}

static void nvme_nvm_set_addr_20(struct nvm_addrf *dst,
				 struct nvme_nvm_id20_addrf *src)
{
	dst->ch_len = src->grp_len;
	dst->lun_len = src->pu_len;
	dst->chk_len = src->chk_len;
	dst->sec_len = src->lba_len;

	dst->sec_offset = 0;
	dst->chk_offset = dst->sec_len;
	dst->lun_offset = dst->chk_offset + dst->chk_len;
	dst->ch_offset = dst->lun_offset + dst->lun_len;

	dst->ch_mask = ((1ULL << dst->ch_len) - 1) << dst->ch_offset;
	dst->lun_mask = ((1ULL << dst->lun_len) - 1) << dst->lun_offset;
	dst->chk_mask = ((1ULL << dst->chk_len) - 1) << dst->chk_offset;
	dst->sec_mask = ((1ULL << dst->sec_len) - 1) << dst->sec_offset;
}

static int nvme_nvm_setup_20(struct nvme_nvm_id20 *id,
			     struct nvm_geo *geo)
{
	geo->major_ver_id = id->mjr;
	geo->minor_ver_id = id->mnr;

	/* Set compacted version for upper layers */
	geo->version = NVM_OCSSD_SPEC_20;

	if (!(geo->major_ver_id == 2 && geo->minor_ver_id == 0)) {
		pr_err("nvm: OCSSD version not supported (v%d.%d)\n",
				geo->major_ver_id, geo->minor_ver_id);
		return -EINVAL;
	}

	geo->num_ch = le16_to_cpu(id->num_grp);
	geo->num_lun = le16_to_cpu(id->num_pu);
	geo->all_luns = geo->num_ch * geo->num_lun;

	geo->num_chk = le32_to_cpu(id->num_chk);
	geo->clba = le32_to_cpu(id->clba);

	geo->all_chunks = geo->all_luns * geo->num_chk;
	geo->total_secs = geo->clba * geo->all_chunks;

	geo->ws_min = le32_to_cpu(id->ws_min);
	geo->ws_opt = le32_to_cpu(id->ws_opt);
	geo->mw_cunits = le32_to_cpu(id->mw_cunits);
	geo->maxoc = le32_to_cpu(id->maxoc);
	geo->maxocpu = le32_to_cpu(id->maxocpu);

	geo->trdt = le32_to_cpu(id->trdt);
	geo->trdm = le32_to_cpu(id->trdm);
	geo->tprt = le32_to_cpu(id->twrt);
	geo->tprm = le32_to_cpu(id->twrm);
	geo->tbet = le32_to_cpu(id->tcrst);
	geo->tbem = le32_to_cpu(id->tcrsm);

	nvme_nvm_set_addr_20(&geo->addrf, &id->lbaf);

	return 0;
}

static int nvme_nvm_identity(struct nvm_dev *nvmdev)
{
	struct nvme_ns *ns = nvmdev->q->queuedata;
	struct nvme_dev *dev = ns->dev;
	struct nvme_nvm_id12 *id;
	struct nvme_nvm_command c = {};
	int ret;

	c.identity.opcode = nvme_nvm_admin_identity;
	c.identity.nsid = cpu_to_le32(ns->ns_id);

	id = kmalloc(sizeof(struct nvme_nvm_id12), GFP_KERNEL);
	if (!id)
		return -ENOMEM;

	ret = nvme_submit_sync_cmd(dev->admin_q, (struct nvme_command *)&c,
				id, sizeof(struct nvme_nvm_id12));
	if (ret) {
		ret = -EIO;
		goto out;
	}

	/*
	 * The 1.2 and 2.0 specifications share the first byte in their geometry
	 * command to make it possible to know what version a device implements.
	 */
	switch (id->ver_id) {
	case 1:
		ret = nvme_nvm_setup_12(id, &nvmdev->geo);
		break;
	case 2:
		ret = nvme_nvm_setup_20((struct nvme_nvm_id20 *)id,
							&nvmdev->geo);
		break;
	default:
		dev_err(dev->device, "OCSSD revision not supported (%d)\n", id->ver_id);
		ret = -EINVAL;
	}

out:
	kfree(id);
	return ret;
}

static int nvme_nvm_get_bb_tbl(struct nvm_dev *nvmdev, struct ppa_addr ppa,
								u8 *blks)
{
	struct request_queue *q = nvmdev->q;
	struct nvm_geo *geo = &nvmdev->geo;
	struct nvme_ns *ns = q->queuedata;
	struct nvme_dev *ctrl = ns->dev;
	struct nvme_nvm_command c = {};
	struct nvme_nvm_bb_tbl *bb_tbl;
	int nr_blks = geo->num_chk * geo->num_pln;
	int tblsz = sizeof(struct nvme_nvm_bb_tbl) + nr_blks;
	int ret = 0;

	c.get_bb.opcode = nvme_nvm_admin_get_bb_tbl;
	c.get_bb.nsid = cpu_to_le32(ns->ns_id);
	c.get_bb.spba = cpu_to_le64(ppa.ppa);

	bb_tbl = kzalloc(tblsz, GFP_KERNEL);
	if (!bb_tbl)
		return -ENOMEM;

	ret = nvme_submit_sync_cmd(ctrl->admin_q, (struct nvme_command *)&c,
								bb_tbl, tblsz);
	if (ret) {
		dev_err(ctrl->device, "get bad block table failed (%d)\n", ret);
		ret = -EIO;
		goto out;
	}

	if (bb_tbl->tblid[0] != 'B' || bb_tbl->tblid[1] != 'B' ||
		bb_tbl->tblid[2] != 'L' || bb_tbl->tblid[3] != 'T') {
		dev_err(ctrl->device, "bbt format mismatch\n");
		ret = -EINVAL;
		goto out;
	}

	if (le16_to_cpu(bb_tbl->verid) != 1) {
		ret = -EINVAL;
		dev_err(ctrl->device, "bbt version not supported\n");
		goto out;
	}

	if (le32_to_cpu(bb_tbl->tblks) != nr_blks) {
		ret = -EINVAL;
		dev_err(ctrl->device,
				"bbt unsuspected blocks returned (%u!=%u)",
				le32_to_cpu(bb_tbl->tblks), nr_blks);
		goto out;
	}

	memcpy(blks, bb_tbl->blk, geo->num_chk * geo->num_pln);
out:
	kfree(bb_tbl);
	return ret;
}

static int nvme_nvm_set_bb_tbl(struct nvm_dev *nvmdev, struct ppa_addr *ppas,
							int nr_ppas, int type)
{
	struct nvme_ns *ns = nvmdev->q->queuedata;
	struct nvme_dev *ctrl = ns->dev;
	struct nvme_nvm_command c = {};
	int ret = 0;

	c.set_bb.opcode = nvme_nvm_admin_set_bb_tbl;
	c.set_bb.nsid = cpu_to_le32(ns->ns_id);
	c.set_bb.spba = cpu_to_le64(ppas->ppa);
	c.set_bb.nlb = cpu_to_le16(nr_ppas - 1);
	c.set_bb.value = type;

	ret = nvme_submit_sync_cmd(ctrl->admin_q, (struct nvme_command *)&c,
								NULL, 0);
	if (ret)
		dev_err(ctrl->device, "set bad block table failed (%d)\n",
									ret);
	return ret;
}

static u64 nvm_cmb_size_unit(struct nvm_dev *dev)
{
	//u8 szu = (dev->cmbsz >> NVME_CMBSZ_SZU_SHIFT) & NVME_CMBSZ_SZU_MASK;
	uint8_t szu = NVME_CMB_SZU(dev->cmbsz);
	return 1ULL << (12 + 4 * szu);
}

static u32 nvm_cmb_size(struct nvm_dev *dev)
{
	//return (dev->cmbsz >> NVME_CMBSZ_SZ_SHIFT) & NVME_CMBSZ_SZ_MASK;
	uint32_t sz = NVME_CMB_SZ(dev->cmbsz);
	return sz;
}

static void nvme_nvm_map_cmb(struct nvm_dev *dev)
{
	u64 size, offset;
	resource_size_t bar_size;
	struct request_queue *q = dev->q;
	struct nvme_ns *ns = q->queuedata;
	struct nvme_dev *ctrl = ns->dev;
	int cmb_bar_id;
	void __iomem *bar;
	struct pci_dev *pdev = to_pci_dev(ctrl->dev);

	bar = ioremap(pci_resource_start(pdev, 0), pci_resource_len(pdev, 0));

	dev->cmbsz = readl(bar + NVME_REG_CMBSZ);
	if (!dev->cmbsz)
		return;
	dev->cmbloc = readl(bar + NVME_REG_CMBLOC);
	printk("ocssd[%s]: cmbsz=%d, cmbloc=%d\n", __func__, dev->cmbsz, dev->cmbloc);
	printk("ocssd[%s]: nvm_cmb_size_unit=%llu nvm_cmb_size=%d\n", __func__, nvm_cmb_size_unit(dev), nvm_cmb_size(dev));

	size = nvm_cmb_size_unit(dev) * nvm_cmb_size(dev);
	offset = nvm_cmb_size_unit(dev) * NVME_CMB_OFST(dev->cmbloc);

	cmb_bar_id = NVME_CMB_BIR(dev->cmbloc);
	bar_size = pci_resource_len(pdev, cmb_bar_id);
	printk("ocssd[%s]: bir=%d, bar_size=%lld KB, cmb_size=%lld KB, offset=%lld KB\n",
			__func__, cmb_bar_id, bar_size/1024, size/1024, offset/1024);
	if (offset > bar_size)
		return;

	/*
	 * Controllers may support a CMB size larger than their BAR,
	 * for example, due to being behind a bridge. Reduce the CMB to
	 * the reported size of the BAR
	 */
	if (size > bar_size - offset)
		size = bar_size - offset;

	dev->cmb = ioremap_wc(pci_resource_start(pdev, cmb_bar_id) + offset, size);
	printk("ocssd[%s]: cmb=%p\n", __func__, dev->cmb);
	if (!dev->cmb)
		return;
	dev->cmb_size = size;
	iounmap(bar);
}

static inline void nvme_nvm_release_cmb(struct nvm_dev *dev)
{
	if (dev->cmb) {
		iounmap(dev->cmb);
		dev->cmb = NULL;
		dev->cmbsz = 0;
	}
}

struct pblk_sec_meta {
	u64 reserved;
	__le64 lba;
};

#define META_SIZE 8
#define META_UNIT_NUMS 64
#define META_UNIT_SIZE (META_SIZE*META_UNIT_NUMS)

//FIXME: why use writel and readl
static void nvme_nvm_cmb_write(struct nvm_dev *dev, struct pblk_sec_meta *meta_list, int meta_id, uint16_t nppas)
{
	//uint32_t meta[32];
	int i;

	for(i=0; i< nppas; i++) {
		//meta[i] = meta_list[i].lba;
		//printk("write meta[%2d]: 0x%08x\n", i, meta[i]);
		writel(meta_list[i].lba, dev->cmb + (meta_id * META_UNIT_SIZE * META_UNIT_NUMS) + i*sizeof(uint64_t));
	}
	//memcpy_toio(dev->cmb + (meta_id*128), meta, nppas*sizeof(uint32_t));
}

static void nvme_nvm_cmb_read(struct nvm_dev *dev, struct pblk_sec_meta *meta_list, int meta_id, uint16_t nppas)
{
	//uint32_t meta[32];
	int i;
	//memcpy_fromio(meta, dev->cmb + (meta_id*128), nppas*sizeof(uint32_t));

	for(i=0; i< nppas; i++) {
		//meta_list[i].lba = meta[i];
		meta_list[i].lba = readl(dev->cmb + (meta_id * META_UNIT_SIZE * META_UNIT_NUMS) + i*sizeof(uint64_t));
		//printk("read meta[%2d]: 0x%08x\n", i, meta[i]);
	}
}

#define META_Q_DEPTH 256
//TODO need malloc data
static bool meta_bit[META_Q_DEPTH] = {false};

static inline void set_meta(int meta_id, bool used)
{
	meta_bit[meta_id] = used;
	//atomic_set(&meta_bit[meta_id], used);
}

int find_first_valid_meta(struct nvm_dev *dev)
{
	int i;
	while(1) {
		spin_lock(&dev->cmb_lock);
		for(i=0; i<META_Q_DEPTH; i++) {
			if(meta_bit[i] == false) {
				meta_bit[i] = true;
				spin_unlock(&dev->cmb_lock);
				return i;
			}
		}
		//printk("ocssd-error[%s]: meta_bit full\n", __func__);
		spin_unlock(&dev->cmb_lock);
		udelay(100);
	}
	printk("ocssd-error[%s]: return -1\n", __func__);
	return -1;
}

static inline void nvme_nvm_rqtocmd(struct nvm_rq *rqd, struct nvme_ns *ns,
				    struct nvme_nvm_command *c)
{
	c->ph_rw.opcode = rqd->opcode;
	c->ph_rw.nsid = cpu_to_le32(ns->ns_id);
	c->ph_rw.spba = cpu_to_le64(rqd->ppa_addr.ppa);
	c->ph_rw.metadata = cpu_to_le64(rqd->dma_meta_list);
	c->ph_rw.control = cpu_to_le16(rqd->flags);
	c->ph_rw.length = cpu_to_le16(rqd->nr_ppas - 1);
}

static void nvme_nvm_end_io(struct request *rq, int error)
{
	struct nvm_rq *rqd = rq->end_io_data;
	int meta_id = rqd->meta_id;

//#ifdef ENABLE_ASYNC_META
	//if(rqd->opcode == NVM_OP_PREAD || rqd->opcode == NVM_OP_PWRITE) {
	if(rqd->opcode == NVM_OP_PWRITE) {
		//if(rqd->opcode == NVM_OP_PREAD) {
		//	if(meta_id < 0 || meta_id >= META_Q_DEPTH)
		//		printk("ocssd-error[%s]: opcode=0x%x, meta_id=%d\n", __func__, rqd->opcode, meta_id);

		//	printk("ocssd[%s]: opcode=0x%x, clean meta_id=%d, meta_list=%p\n", __func__, rqd->opcode, meta_id, rqd->meta_list);
		//	nvme_nvm_cmb_read(rqd->dev->parent, rqd->meta_list, meta_id, rqd->nr_ppas);
		//}
		set_meta(meta_id, false);
	}
//#else
//	if(rqd->opcode == NVM_OP_PWRITE) {
//		//spin_lock(&rqd->dev->parent->cmb_lock);
//		//printk("ocssd[%s]: opcode=0x%x, clean meta_id=%d\n", __func__, rqd->opcode, meta_id);
//		set_meta(meta_id, false);
//		//spin_unlock(&rqd->dev->parent->cmb_lock);
//	}
//#endif

	//rqd->ppa_status = le64_to_cpu(nvme_req(rq)->result.u64);
	//rqd->error = nvme_req(rq)->status;
	rqd->ppa_status = (unsigned long)rq->special;
	rqd->error = rq->errors;
	
	pblk_end_io(rqd);//bookmark: async io callback function

	//kfree(nvme_req(rq)->cmd);
	kfree(rq->cmd);
	blk_mq_free_request(rq);
}

static int nvme_nvm_submit_io(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	struct request_queue *q = dev->q;
	struct nvme_ns *ns = q->queuedata;
	struct request *rq;
	struct bio *bio = rqd->bio;
	struct nvme_nvm_command *cmd;
	int meta_id;
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	int rw;

	if(bio) {
		rw = bio_rw(bio);
	} else {
		rw = 0;
	}
	rq = blk_mq_alloc_request(q, rw, GFP_KERNEL, 0);
	if (IS_ERR(rq))
		return -ENOMEM;

	cmd = kzalloc(sizeof(struct nvme_nvm_command), GFP_KERNEL);
	if (!cmd) {
		blk_mq_free_request(rq);
		return -ENOMEM;
	}

	rq->cmd_type = REQ_TYPE_DRV_PRIV;
	if(bio) {
		rq->ioprio = bio_prio(bio);

		if (bio_has_data(bio))
			rq->nr_phys_segments = bio_phys_segments(q, bio);

		rq->__data_len = bio->bi_iter.bi_size;
		rq->bio = rq->biotail = bio;
	} else {
		rq->ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, IOPRIO_NORM);
		rq->__data_len = 0;
	}

	nvme_nvm_rqtocmd(rqd, ns, cmd);

	rq->cmd = (unsigned char *)cmd;
	rq->cmd_len = sizeof(struct nvme_nvm_command);
	rq->special = (void *)0;

	//bookmark: write meta
	//rqd->meta_id = 0xffffffff;//FIXME 若设为ff,写就直接bug
//#ifdef ENABLE_ASYNC_META
	//if(rqd->opcode == NVM_OP_PREAD || rqd->opcode == NVM_OP_PWRITE) {
//#else
	if(rqd->opcode == NVM_OP_PWRITE) {
//#endif
		meta_id = find_first_valid_meta(dev);
		rqd->meta_id = cmd->ph_rw.rsvd2 = meta_id;
		//printk("ocssd[%s]: opcode=0x%x, set meta_id=%d\n", __func__, rqd->opcode, meta_id);
		//if(rqd->opcode == NVM_OP_PWRITE) {
		nvme_nvm_cmb_write(dev, meta_list, meta_id, rqd->nr_ppas);
		//}
	}
	rq->end_io_data = rqd;

	blk_execute_rq_nowait(q, NULL, rq, 0, nvme_nvm_end_io);

	return 0;
}

static int nvme_nvm_submit_io_sync(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	struct request_queue *q = dev->q;
	struct nvme_ns *ns = q->queuedata;
	struct request *rq;
	struct bio *bio = rqd->bio;
	struct nvme_nvm_command *cmd;
	int meta_id;
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	int ret = 0;
	int rw;

	if(bio) {
		rw = bio_rw(bio);
	} else {
		rw = 0;
	}
	rq = blk_mq_alloc_request(q, rw, GFP_KERNEL, false);
	if (IS_ERR(rq))
		return -ENOMEM;

	cmd = kzalloc(sizeof(struct nvme_nvm_command), GFP_KERNEL);
	if (!cmd) {
		blk_mq_free_request(rq);
		return -ENOMEM;
	}

	rq->cmd_type = REQ_TYPE_DRV_PRIV;
	if(bio) {
		rq->ioprio = bio_prio(bio);

		if (bio_has_data(bio))
			rq->nr_phys_segments = bio_phys_segments(q, bio);

		rq->__data_len = bio->bi_iter.bi_size;
		rq->bio = rq->biotail = bio;
	} else {
		rq->ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, IOPRIO_NORM);
		rq->__data_len = 0;
	}

	nvme_nvm_rqtocmd(rqd, ns, cmd);

	rq->cmd = (unsigned char *)cmd;
	rq->cmd_len = sizeof(struct nvme_nvm_command);
	rq->special = (void *)0;

	//bookmark
	if(rqd->opcode == NVM_OP_PREAD || rqd->opcode == NVM_OP_PWRITE) {
		meta_id = find_first_valid_meta(dev);
		//printk("ocssd[%s]: opcode=0x%x, set meta_id=%d, nr_ppas=%d, meta_list=%p\n", __func__, rqd->opcode, meta_id, rqd->nr_ppas, meta_list);
		rqd->meta_id = cmd->ph_rw.rsvd2 = meta_id;
		if(rqd->opcode == NVM_OP_PWRITE) {
			nvme_nvm_cmb_write(dev, meta_list, meta_id, rqd->nr_ppas);
		}
	}

	/* I/Os can fail and the error is signaled through rqd. Callers must
	 * handle the error accordingly.
	 */
	blk_execute_rq(q, NULL, rq, 0);
	//if (nvme_req(rq)->flags & NVME_REQ_CANCELLED)
		//ret = -EINTR;

	rqd->ppa_status = (unsigned long)rq->special;
	rqd->error = rq->errors;

	if(rqd->opcode == NVM_OP_PREAD || rqd->opcode == NVM_OP_PWRITE) {
		if(rqd->opcode == NVM_OP_PREAD) {
			nvme_nvm_cmb_read(dev, meta_list, meta_id, rqd->nr_ppas);
		}
		//printk("ocssd[%s]: opcode=0x%x, clean meta_id=%d\n", __func__, rqd->opcode, meta_id);
		set_meta(meta_id, false);
	}
	kfree(rq->cmd);
	blk_mq_free_request(rq);

	return ret;
}

static void *nvme_nvm_create_dma_pool(struct nvm_dev *nvmdev, char *name)
{
	struct nvme_ns *ns = nvmdev->q->queuedata;
	struct nvme_dev *ctrl = ns->dev;

	return dma_pool_create(name, ctrl->dev, PAGE_SIZE, PAGE_SIZE, 0);
}

static void nvme_nvm_destroy_dma_pool(void *pool)
{
	struct dma_pool *dma_pool = pool;

	dma_pool_destroy(dma_pool);
}

static void *nvme_nvm_dev_dma_alloc(struct nvm_dev *dev, void *pool,
				    gfp_t mem_flags, dma_addr_t *dma_handler)
{
	return dma_pool_alloc(pool, mem_flags, dma_handler);
}

static void nvme_nvm_dev_dma_free(void *pool, void *addr,
							dma_addr_t dma_handler)
{
	dma_pool_free(pool, addr, dma_handler);
}

static struct nvm_dev_ops nvme_nvm_dev_ops = {
	.identity		= nvme_nvm_identity,

	.get_bb_tbl		= nvme_nvm_get_bb_tbl,
	.set_bb_tbl		= nvme_nvm_set_bb_tbl,

	.submit_io		= nvme_nvm_submit_io,
	.submit_io_sync		= nvme_nvm_submit_io_sync,

	.create_dma_pool	= nvme_nvm_create_dma_pool,
	.destroy_dma_pool	= nvme_nvm_destroy_dma_pool,
	.dev_dma_alloc		= nvme_nvm_dev_dma_alloc,
	.dev_dma_free		= nvme_nvm_dev_dma_free,
};

void nvme_nvm_update_nvm_info(struct nvme_ns *ns)
{
	struct nvm_dev *ndev = ns->ndev;
	struct nvm_geo *geo = &ndev->geo;

	geo->csecs = 1 << ns->lba_shift;
	//printk("ocssd[%s]: change csecs=%d\n", __func__, geo->csecs);
	geo->sos = ns->ms;
}

int nvme_nvm_register(struct nvme_ns *ns, char *disk_name)
{
	struct request_queue *q = ns->queue;
	struct nvm_dev *dev;

	dev = kzalloc(sizeof(struct nvm_dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->q = q;
	memcpy(dev->name, disk_name, DISK_NAME_LEN);
	dev->ops = &nvme_nvm_dev_ops;
	dev->private_data = ns;
	ns->ndev = dev;

	printk("ocssd[%s]: disk_name=%s\n", __func__, disk_name);
	nvme_nvm_map_cmb(dev);
	return pblk_nvm_register(dev);
}

void nvme_nvm_unregister(struct nvme_ns *ns)
{
	printk("ocssd[%s]: exit\n", __func__);
	pblk_nvm_unregister(ns->ndev);
}
