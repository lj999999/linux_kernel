/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2016-2019, 2021, The Linux Foundation. All rights reserved.
 */

#ifndef __LINUX_XRING_DMA_MAP_H
#define __LINUX_XRING_DMA_MAP_H

#include <linux/iommu.h>
#include <linux/rbtree.h>
//#include <sys/types.h>

#define IOVA_DEFAULT_ADDS		0x0
#define IOVA_DEFAULT_SIZE		0x100000000//2^32 = 4G
#define IOVA_DEFAULT_PARA_NUM           2
#define LAZY_FREE_WATERLINE	10
#define PINGPONG_SHIFT 35
#define PINGPONG_MASK (1UL <<  PINGPONG_SHIFT)
#define IOVA_SIZE_MASK (PINGPONG_MASK - 1)
#define WATCHDOG_CPU	0
#define WIFI_INTX_CPU	4
#define LAZY_FREE_SCHED_PRI	97

struct dma_iommu_mapping;
struct io_pgtable_ops;
struct iova_domain;

struct sched_param {
	int sched_priority;
};

enum iova_free_type {
	IMME_FREE, /* Immediately free */
	LAZY_FREE, /* lazy free */
};

struct iommu_domain_data {
	unsigned long iova_start;
	unsigned long iova_size;
};

struct mm_iova_lazy_free {
	u32 pingpong;
	unsigned long pages;
	unsigned long waterline;
	bool end;
	wait_queue_head_t wait_q;
	struct task_struct *task;
	struct mutex mutex;
	spinlock_t lock;
};

struct dma_fast_smmu_mapping {
	struct device		*dev;
	struct iommu_domain	*domain;
	struct iova_domain	*iovad;
#define IOVA_MAX_NUM      3
        struct iommu_domain_data         iova[IOVA_MAX_NUM];
        struct iommu_domain_data         iova_res;
        unsigned long iova_pool_num;
        unsigned long iova_align;
        unsigned long iova_free;
        unsigned long iova_totol_size;

	spinlock_t lock;
	struct gen_pool *iova_pool;
	struct mm_iova_lazy_free *lazy_free;
        u32  *free_size[IOVA_MAX_NUM];

	dma_addr_t	 base;
	size_t		 size;
//	size_t		 num_4k_pages;

//	unsigned int	bitmap_size;
	/* bitmap has 1s marked only valid mappings */
	//unsigned long	*bitmap;
	/* clean_bitmap has 1s marked for both valid and stale tlb mappings */
	//unsigned long	*clean_bitmap;

	//unsigned long	next_start;
	//bool		have_stale_tlbs;

	dma_addr_t	pgtbl_dma_handle;
	struct io_pgtable_ops *pgtbl_ops;

	struct notifier_block notifier;
	struct rb_node node;
};

int xring_fast_smmu_init_mapping(struct device *dev, struct iommu_domain *domain,
			   struct io_pgtable_ops *pgtable_ops);

#endif /* __LINUX_DMA_MAPPING_FAST_H */
