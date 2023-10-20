// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2016-2021, The Linux Foundation. All rights reserved.
 */
#include <asm-generic/errno-base.h>
#include <linux/dma-map-ops.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/pci.h>
#include <linux/iova.h>
#include <linux/io-pgtable.h>
#include <linux/rwlock.h>
#include <test_dma/xring_dma_map.h>
#include <linux/genalloc.h>
#include <linux/kthread.h>

/* some redundant definitions... :( TODO: move to io-pgtable-fast.h */
#define FAST_PAGE_SHIFT		12
#define FAST_PAGE_SIZE (1UL << FAST_PAGE_SHIFT)
#define FAST_PAGE_MASK (~(PAGE_SIZE - 1))

static struct rb_root mappings;
static DEFINE_RWLOCK(mappings_lock);

static int fast_smmu_add_mapping(struct dma_fast_smmu_mapping *fast)
{
	struct rb_node **new = &mappings.rb_node, *parent = NULL;
	struct dma_fast_smmu_mapping *entry;
	int ret = 0;
	unsigned long flags;

	write_lock_irqsave(&mappings_lock, flags);
	while (*new) {
		entry = rb_entry(*new, struct dma_fast_smmu_mapping, node);

		parent = *new;
		if (fast->domain < entry->domain) {
			new = &((*new)->rb_left);
		} else if (fast->domain > entry->domain) {
			new = &((*new)->rb_right);
		} else {
			ret = -EEXIST;
			break;
		}
	}

	if (!ret) {
		rb_link_node(&fast->node, parent, new);
		rb_insert_color(&fast->node, &mappings);
	}
	write_unlock_irqrestore(&mappings_lock, flags);

	return ret;
}

static struct dma_fast_smmu_mapping *__fast_smmu_lookup_mapping(struct iommu_domain *domain)
{
	struct rb_node *node = mappings.rb_node;
	struct dma_fast_smmu_mapping *entry;

	while (node) {
		entry = rb_entry(node, struct dma_fast_smmu_mapping, node);

		if (domain < entry->domain)
			node = node->rb_left;
		else if (domain > entry->domain)
			node = node->rb_right;
		else
			return entry;
	}

	return NULL;
}

static struct dma_fast_smmu_mapping *fast_smmu_lookup_mapping(struct iommu_domain *domain)
{
	struct dma_fast_smmu_mapping *fast;
	unsigned long flags;

	read_lock_irqsave(&mappings_lock, flags);
	fast = __fast_smmu_lookup_mapping(domain);
	read_unlock_irqrestore(&mappings_lock, flags);
	return fast;
}

static struct dma_fast_smmu_mapping *dev_get_mapping(struct device *dev)
{
	struct iommu_domain *domain;

	domain = iommu_get_domain_for_dev(dev);
	if (!domain)
		return ERR_PTR(-EINVAL);
	return fast_smmu_lookup_mapping(domain);
}

static void *fast_smmu_alloc(struct device *dev, size_t size,
			     dma_addr_t *handle, gfp_t gfp,
			     unsigned long attrs)
{
        return NULL;
}

struct gen_pool *iova_pool_setup(struct iommu_domain_data *iova, unsigned long num,
                                unsigned long align)
{
	struct gen_pool *pool = NULL;
	int ret;
        uint i = 0;
	pool = gen_pool_create(order_base_2(align), -1);/*lint !e666 */
	if (!pool) {
		pr_err("create gen pool failed!\n");
		return NULL;
	}

	pr_err("num:0x%lx\n", num);
        for (i = 0; i < num; i++) {
        	/*
	        * iova start should not be 0, because return
	        * 0 when alloc iova is considered as error
	        */    
        	
		pr_err("iova->iova_start:0x%lx, iova->iova_size:0x%lx\n", iova->iova_start, iova->iova_size);
                ret = gen_pool_add(pool, iova->iova_start, iova->iova_size, -1);
	        if (ret) {
		        pr_err("gen pool add failed!\n");
		        gen_pool_destroy(pool);
		        return NULL;
	        }
                iova++;
        }        

	return pool;
}

static void xring_smmu_flush_tlb(struct device *dev, struct iommu_domain *domain)
{
        return ;
}

static void xring_smmu_iova_lazy_free(struct dma_fast_smmu_mapping *fast)
{
        unsigned int pages_num, i, size, pong;
	unsigned int pingpong;
	unsigned long iova_start;
	u32 *free_size = NULL;

	pingpong = 1UL - fast->lazy_free->pingpong;
        for (i = 0; i < fast->iova_pool_num; i++) {
	        pages_num = DIV_ROUND_UP(fast->iova[i].iova_size, PAGE_SIZE);
	        iova_start = fast->iova[i].iova_start;
	        free_size = fast->free_size[i];
        }
	mutex_lock(&fast->lazy_free->mutex);
	for (i = 0; i < pages_num; i++) {
		size = free_size[i] & IOVA_SIZE_MASK;
		if (size == 0)
			continue;

		pong = (free_size[i] & PINGPONG_MASK) >> PINGPONG_SHIFT;
		if (pong != pingpong)
			continue;

		free_size[i] = 0;
		gen_pool_free(fast->iova_pool,
			(iova_start + ((unsigned long)i << PAGE_SHIFT)), size);
	}
	mutex_unlock(&fast->lazy_free->mutex);
	fast->lazy_free->end = true;
}

static int xring_smmu_iova_lazy_free_thread(void *p)
{
        struct device *dev = (struct device *)p;
	struct iommu_domain *domain = NULL;
	struct dma_fast_smmu_mapping *fast = NULL;
	DEFINE_WAIT(wait);

	domain = iommu_get_domain_for_dev(dev);
	if (!domain) {
		dev_err(dev, "%s, domain is null\n", __func__);
		return -ENOENT;
	}

	fast = fast_smmu_lookup_mapping(domain);
	if (!fast) {
		dev_err(dev, "%s, iova_cookie is null\n", __func__);
		return -ENOENT;
	}

	while (!kthread_should_stop()) {
		prepare_to_wait(&fast->lazy_free->wait_q, &wait,
			TASK_UNINTERRUPTIBLE);
		schedule();
		finish_wait(&fast->lazy_free->wait_q, &wait);
		xring_smmu_flush_tlb(dev, domain);
		xring_smmu_iova_lazy_free(fast);
	}
	return 0;
}

static void xring_smmu_init_iova_lazy_free(struct device *dev,
                struct dma_fast_smmu_mapping *fast)
{
	int ret;
	unsigned int pages_num, i = 0;
	struct cpumask sched_cpus;
	struct mm_iova_lazy_free *lazy_free = NULL;
	struct sched_param param;

	if (fast->iova_free == IMME_FREE)
		return;

	lazy_free = kzalloc(sizeof(*lazy_free), GFP_KERNEL);
	if (!lazy_free)
		goto out_err;

        do {
        	pages_num = DIV_ROUND_UP(fast->iova[i].iova_start, PAGE_SIZE);
	        fast->free_size[i] = kcalloc(pages_num, sizeof(u32), GFP_KERNEL);
	        if (!fast->free_size[i])
		        goto out_free;
        } while(i < fast->iova_pool_num);

	init_waitqueue_head(&lazy_free->wait_q);
	mutex_init(&lazy_free->mutex);
	spin_lock_init(&lazy_free->lock);
	lazy_free->end = true;
        pages_num = DIV_ROUND_UP(fast->iova_totol_size, PAGE_SIZE);
	lazy_free->waterline = pages_num / LAZY_FREE_WATERLINE;
	if (lazy_free->waterline < LAZY_FREE_WATERLINE) {
		dev_info(dev, "%s,iova_size %lu too small,disable lazy free\n",
			__func__, fast->iova_totol_size);
		goto out_free;
	}
	fast->lazy_free = lazy_free;

	lazy_free->task = kthread_run(xring_smmu_iova_lazy_free_thread, dev,
		"iova.%s", dev_name(dev));
	if (IS_ERR(lazy_free->task)) {
		dev_err(dev, "%s, create lazy free task err %d\n",
			__func__, IS_ERR(lazy_free->task));
		goto out_stop;
	}

	cpumask_setall(&sched_cpus);
	cpumask_clear_cpu(WATCHDOG_CPU, &sched_cpus);
	cpumask_clear_cpu(WIFI_INTX_CPU, &sched_cpus);
	set_cpus_allowed_ptr(lazy_free->task, &sched_cpus);

	/* set thread priority and schedule policy */
	param.sched_priority = LAZY_FREE_SCHED_PRI;
	ret = sched_setscheduler(lazy_free->task, SCHED_RR, &param);
	if (ret)
		dev_info(dev, "%s, task set priority error\n", __func__);

	dev_info(dev, "%s, iova lazy free waterline %lu\n",
		__func__, lazy_free->waterline);

	return;

out_stop:
        for (i = 0; i < fast->iova_pool_num && fast->free_size[i]; i++)
	        kfree(fast->free_size[i]);
	fast->lazy_free = NULL;
out_free:
	kfree(lazy_free);
out_err:
	fast->iova_free = IMME_FREE;
	dev_err(dev, "%s iova_free rollback imme free!\n", __func__);
}

static void xring_iommu_free_iova(struct gen_pool *iova_pool,
                unsigned long iova, size_t size)
{
	if (!iova_pool)
		return;

	gen_pool_free(iova_pool, iova, size);
}

static void xring_iommu_lazy_free_iova(struct dma_fast_smmu_mapping *fast,
                unsigned long iova, size_t size)
{
	u32 ping;
	u64 iova_end;
	unsigned int bgn_page, i;
	unsigned long flag;
        u32 *free_size = NULL;
	unsigned int page_num = size >> PAGE_SHIFT;
	struct mm_iova_lazy_free *lazy_free = NULL;

        for (i = 0; i < fast->iova_pool_num; i++) {
                iova_end = fast->iova[i].iova_start + fast->iova[i].iova_size;
                if ((iova < fast->iova[i].iova_start) || (iova + size) > iova_end)
                        continue;
                return ;
        }
        if (((iova < fast->iova[i].iova_start) || (iova + size) > iova_end) &&
                i == fast->iova_pool_num) {
		pr_err("%s, iova 0x%lx err\n", __func__, iova);
		return;
        }

	if (size > IOVA_SIZE_MASK) {
		pr_err("%s, iova 0x%lx iova size 0x%lx err\n",
			__func__, iova, size);
		return;
	}

	lazy_free = fast->lazy_free;
	if (!lazy_free) {
		pr_err("%s, lazy free is null\n", __func__);
		return;
	}

        if (i == fast->iova_pool_num)
                i -= 1;

        free_size = fast->free_size[i];
	spin_lock_irqsave(&lazy_free->lock, flag);
	ping = lazy_free->pingpong;
	bgn_page = (iova - fast->iova[i].iova_start) >> PAGE_SHIFT;
	if (free_size[bgn_page] != 0) {
		pr_err("%s, iova 0x%lx free err, size 0x%lx\n",
			__func__, iova, size);
		return;
	}
	free_size[bgn_page] = (u32)size | (ping << PINGPONG_SHIFT);
	lazy_free->pages += page_num;

	if (lazy_free->pages >= lazy_free->waterline) {
		if (lazy_free->end) {
			lazy_free->pages = 0;
			lazy_free->pingpong = 1 - ping;
			lazy_free->end = false;
			wake_up(&lazy_free->wait_q);
		}
	}
	spin_unlock_irqrestore(&lazy_free->lock, flag);
}

static const struct dma_map_ops fast_smmu_dma_ops = {
	.alloc = fast_smmu_alloc,
};

static int of_get_iova_info_smmu(struct device_node *np,
				struct dma_fast_smmu_mapping *fast)
{
	struct device_node *node = NULL;
	int ret;
        uint count, size, i = 0;

	fast->iova[i].iova_start = IOVA_DEFAULT_ADDS;
	fast->iova[i].iova_size = IOVA_DEFAULT_SIZE;
	fast->iova_align = PAGE_SIZE;
        fast->iova_pool_num = 1;


	if (!np)
		return -ENODEV;

	node = of_get_child_by_name(np, "iova_info");
	if (!node) {
		pr_err("no iova_info, default cfg(0x%lx, 0x%lx)\n",
			fast->iova[0].iova_start, fast->iova[0].iova_size);
		return 0;
	}

        ret = of_property_read_u64(node, "iova-align",
                (u64 *)&fast->iova_align);
        if (ret)
                pr_err("read iova align error\n");

        ret = of_property_read_u32(node, "iova-free",
                (u32 *)&fast->iova_free);
        if (ret)
                pr_err("read iova free is default\n"); 

        //iova resource
        ret = of_property_read_u64_array(node, "iova-resource",
                (u64 *)&fast->iova_res, sizeof(struct iommu_domain_data));
	pr_err("iova_res_info, cfg(0x%lx, 0x%lx, 0x%lx, %u)\n",
		fast->iova_res.iova_start, fast->iova_res.iova_size);
	
        count = of_property_count_u64_elems(node, "iova-management");
        if (count < 0 || count % IOVA_DEFAULT_PARA_NUM)
                return -EINVAL;

        size = count / IOVA_DEFAULT_PARA_NUM;
        fast->iova_pool_num = size;
        for (i = 0; i < size; i++) {
                of_property_read_u32_index(node, "iova-management",
                        IOVA_DEFAULT_PARA_NUM * i, (u32 *)&fast->iova[i]);
	        pr_err("%s 0x%lx:start_addr 0x%lx, size 0x%lx align 0x%lx, free %u\n",
			__func__, i, fast->iova[i].iova_start, fast->iova[i].iova_size);
                fast->iova_totol_size += fast->iova[i].iova_size;
        }

	pr_err("iova_pool_num:0x%lx, range_totol_size:0x%lx\n", fast->iova_pool_num, fast->iova_totol_size);
	return 0;
}

/**
 * __fast_smmu_create_mapping_sized
 *
 * Creates a mapping structure which holds information about used/unused IO
 * address ranges, which is required to perform mapping with IOMMU aware
 * functions. The only VA range supported is [0, 4GB).
 *
 * The client device need to be attached to the mapping with
 * fast_smmu_attach_device function.
 */
static struct dma_fast_smmu_mapping *__fast_smmu_create_mapping_sized(
	struct device *dev)
{
	struct dma_fast_smmu_mapping *fast;
        
	fast = kzalloc(sizeof(struct dma_fast_smmu_mapping), GFP_KERNEL);
	if (!fast)
		goto err;
        
        if (of_get_iova_info_smmu(dev->of_node, fast)) 
                return -ENODEV;

	pr_err("iova_pool_num:0x%lx\n", fast->iova_pool_num);

        fast->iova_pool = iova_pool_setup(fast->iova, fast->iova_pool_num, fast->iova_align);
        if (!fast->iova_pool) {
                pr_err("setup dev(%s) iova pool fail\n", dev_name(dev));
                goto err1;
        }

	return fast;

err1:
	kfree(fast);
err:
	return ERR_PTR(-ENOMEM);
}

unsigned long xring_iommu_iova_alloc(struct gen_pool *iova_pool,
        size_t size, unsigned long align)
{
        unsigned long iova;
	if (iova_pool->min_alloc_order >= 0) {
		if (align > (1UL << (unsigned long)iova_pool->min_alloc_order))
			WARN(1, "iommu domain cant align to 0x%lx\n",
			     align);
	} else {
		pr_warn("The min_alloc_order of iova_pool is negative!\n");
		return 0;
	}

	iova = gen_pool_alloc(iova_pool, size);

	return iova;        
}
EXPORT_SYMBOL(xring_iommu_iova_alloc);

void xring_iommu_iova_free(struct device *dev, unsigned long iova, size_t size)
{
	struct iommu_domain *domain = NULL;
        struct dma_fast_smmu_mapping *fast = NULL; 

        domain = iommu_get_domain_for_dev(dev);
        if (!domain) {
                pr_err("Dev(%s) has no iommu domain!\n", dev_name(dev));
                return ;
        }
	
	fast = fast_smmu_lookup_mapping(domain);
        if (!fast) {
                dev_err(dev, "%s, fast_mapping is null!\n", __func__);
                return ;   
        }

        if (fast->iova_free == LAZY_FREE) {
                xring_iommu_lazy_free_iova(fast, iova, size);
        }

        xring_smmu_flush_tlb(dev, domain);
        xring_iommu_free_iova(fast->iova_pool, iova, size);
}
EXPORT_SYMBOL(xring_iommu_iova_free);

/**
 * fast_smmu_init_mapping
 * @dev: valid struct device pointer
 * @domain: valid IOMMU domain pointer
 * @pgtable_ops: The page table ops associated with this domain
 *
 * Called the first time a device is attached to this mapping.
 * Not for dma client use.
 */
int xring_fast_smmu_init_mapping(struct device *dev, struct iommu_domain *domain,
			   struct io_pgtable_ops *pgtable_ops)
{
	struct dma_fast_smmu_mapping *fast = fast_smmu_lookup_mapping(domain);

	if (fast) {
		dev_err(dev, "Iova cookie already present\n");
		return -EINVAL;
	}

	if (!pgtable_ops)
		return -EINVAL;
	
        fast = __fast_smmu_create_mapping_sized(dev);
	if (IS_ERR(fast))
		return -ENOMEM;

	fast->domain = domain;
	fast->dev = dev;
	fast_smmu_add_mapping(fast);

	fast->pgtbl_ops = pgtable_ops;

	xring_smmu_init_iova_lazy_free(dev, fast);

	return 0;
}
EXPORT_SYMBOL(xring_fast_smmu_init_mapping);

static void __xring_fast_smmu_setup_dma_ops(void *data, struct device *dev,
					u64 dma_base, u64 size)
{
	struct dma_fast_smmu_mapping *fast;
	struct iommu_domain *domain;
	int is_fast;
	int ret;

	domain = iommu_get_domain_for_dev(dev);
	if (!domain)
		return;

	fast = dev_get_mapping(dev);
	if (!fast) {
		dev_err(dev, "Missing fastmap iova cookie\n");
		return;
	}

	dev->dma_ops = &fast_smmu_dma_ops;
}

/*
 * Called by drivers who create their own iommu domains via
 * iommu_domain_alloc().
 */
void xring_fast_smmu_setup_dma_ops(struct device *dev, u64 dma_base, u64 size)
{
	__xring_fast_smmu_setup_dma_ops(NULL, dev, dma_base, size);
}
EXPORT_SYMBOL(xring_fast_smmu_setup_dma_ops);

#if 0
int __init dma_mapping_fast_init(void)
{
	return register_trace_android_vh_iommu_setup_dma_ops(
			__fast_smmu_setup_dma_ops, NULL);
}

void dma_mapping_fast_exit(void)
{
	unregister_trace_android_vh_iommu_setup_dma_ops(
			__fast_smmu_setup_dma_ops, NULL);
}
#endif