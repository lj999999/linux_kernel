#include <linux/dma-iommu.h>
#include <linux/dma-mapping.h>
#include <linux/dma-mapping-fast.h>
#include <linux/qcom-dma-mapping.h>
#include <linux/dma-map-ops.h>
//#include <linux/io-pgtable-fast.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/pci.h>
#include <linux/iova.h>
#include <linux/io-pgtable.h>
#include <linux/rwlock.h>
//#include <linux/qcom-iommu-util.h>
#include <trace/hooks/iommu.h>

#define DEBUG_ON_QEMU


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

	ret = iommu_domain_get_attr(domain, DOMAIN_ATTR_FAST, &is_fast);
	if (ret || !is_fast)
		return;

	fast = dev_get_mapping(dev);
	if (!fast) {
		dev_err(dev, "Missing fastmap iova cookie\n");
		return;
	}

	//fast_smmu_reserve_iommu_regions(dev, fast);
	dev->dma_ops = &xring_fast_smmu_dma_ops;
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

#ifndef DEBUG_ON_QEMU
int __init xring_dma_mapping_fast_init(void)
{
		return register_trace_android_vh_iommu_setup_dma_ops(
			__xring_fast_smmu_setup_dma_ops, NULL);
}

void xring_dma_mapping_fast_exit(void)
{
	unregister_trace_android_vh_iommu_setup_dma_ops(
			__fast_smmu_setup_dma_ops, NULL);
}
#endif

