#include <linux/module.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/ioctl.h>
#include <linux/dma-mapping.h>
#include <linux/dma-map-ops.h>
#include <linux/dma-iommu.h>
#include <linux/dmaengine.h>
#include <linux/jiffies.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <uapi/linux/dma-heap.h>
#include <linux/of_reserved_mem.h>

#define TEST_DMA_IOC_MAGIC          'M'
#define TEST_DMA_INIT_DMA           _IOWR(TEST_DMA_IOC_MAGIC, 0, int)
#define TEST_DMA_MEMCPY             _IOWR(TEST_DMA_IOC_MAGIC, 1, int)
#define TEST_DMA_RELEASE_DMA        _IOWR(TEST_DMA_IOC_MAGIC, 2, int)
#define TEST_DMA_VMAP               _IOWR(TEST_DMA_IOC_MAGIC, 3, int)
#define TEST_DMA_VUNMAP             _IOWR(TEST_DMA_IOC_MAGIC, 4, int)
#define TEST_DMA_RESERVE_MEM        _IOWR(TEST_DMA_IOC_MAGIC, 5, int)

#define BUFLEN (unsigned long long)4096

struct testdma_t {
    struct device               *misc_parent;
    struct mutex                mutex;
    unsigned int                dma_finished;
    struct dma_chan             *chan;
    void*                       src_virt;
    void*                       dst_virt;
    dma_addr_t                  src_phys;
    dma_addr_t                  dst_phys;

    struct dma_buf              *dma_buf;
    struct dma_buf_attachment   *attachment;
    struct sg_table             *sgt;
    char                        *buf;
    int                         len;
    int                         fd;

    wait_queue_head_t wq;
};

static struct testdma_t *gdata = NULL;

static void test_dma_callback(void *dma_async_param)
{
    gdata->dma_finished = 1;
    printk(KERN_ERR "callback\n");
    wake_up_interruptible(&gdata->wq);
    printk(KERN_ERR "dst:%s\n", (char *)gdata->dst_virt);
}

static int test_dma_init_dma(void)
{
    int ret = 0;
    dma_cap_mask_t mask;
    struct dma_chan *chan = NULL;

    dma_cap_zero(mask);
    dma_cap_set(DMA_MEMCPY, mask);

    chan = dma_request_channel(mask, NULL, NULL);
    if (!chan) {
        printk(KERN_ERR "dma_request_channel failed\n");
        ret = -1;
        goto fail_dma_req;
    }

    gdata->src_virt = dma_alloc_coherent(chan->device->dev, BUFLEN, &(gdata->src_phys), GFP_KERNEL);
    if (!gdata->src_virt) {
        printk(KERN_ERR "dma_alloc src failed\n");
        ret = -1;
        goto fail_dma_alloc_src;
    }

    gdata->dst_virt = dma_alloc_coherent(chan->device->dev, BUFLEN, &(gdata->dst_phys), GFP_KERNEL);
    if (!gdata->dst_virt) {
        printk(KERN_ERR "dma_alloc dst failed\n");
        ret = -1;
        goto fail_dma_alloc_dst;
    }
    pr_err("src_phys:%llx, dst_phys:%llx\n", gdata->src_phys, gdata->dst_phys);
    strcpy((char *)gdata->src_virt, "hello,world");

    gdata->chan             = chan;
    gdata->dma_finished     = 0;

    return 0;

fail_dma_alloc_dst:
    dma_free_coherent(chan->device->dev, BUFLEN, gdata->src_virt, gdata->src_phys);
fail_dma_alloc_src:
    dma_release_channel(gdata->chan);
fail_dma_req:
    return ret;
}

static int test_dma_release_dma(void)
{
    struct dma_chan *chan = gdata->chan;
    if (chan) {
        dma_free_coherent(chan->device->dev, BUFLEN, gdata->src_virt, gdata->src_phys);
        dma_free_coherent(chan->device->dev, BUFLEN, gdata->dst_virt, gdata->dst_phys);
    }
    return 0;
}

static int test_dma_memcpy(void)
{
#ifndef CONFIG_IOMMU_USE_DMA_OPS
    struct device *dev;
    dma_addr_t iova_src, iova_dst;
#endif
    dma_cookie_t dma_cookie;
    struct dma_chan *chan = gdata->chan;
    struct dma_async_tx_descriptor *tx = NULL;
    struct dma_map_ops *ops = NULL;

    gdata->dma_finished = 0;
#ifndef CONFIG_IOMMU_USE_DMA_OPS
    dev = chan->device->dev;
#if 0
    iova_src = __iommu_dma_map(dev, gdata->src_phys, BUFLEN,
            IOMMU_READ|IOMMU_WRITE, dma_get_mask(dev));
    iova_dst = __iommu_dma_map(dev, gdata->dst_phys, BUFLEN,
            IOMMU_READ|IOMMU_WRITE, dma_get_mask(dev));
#endif
    ops = get_dma_ops(dev);
    iova_src = ops->map_resource(dev, gdata->src_phys, BUFLEN,
            IOMMU_READ|IOMMU_WRITE, dma_get_mask(dev));
    iova_dst = ops->map_resource(dev, gdata->dst_phys, BUFLEN,
            IOMMU_READ|IOMMU_WRITE, dma_get_mask(dev));
    tx = dmaengine_prep_dma_memcpy(chan, iova_dst, iova_src, BUFLEN,
                                    DMA_PREP_INTERRUPT|DMA_CTRL_ACK);
#else
    tx = dmaengine_prep_dma_memcpy(chan, gdata->dst_phys, gdata->src_phys, BUFLEN,
                                    DMA_PREP_INTERRUPT|DMA_CTRL_ACK);
#endif
    if (!tx) {
        dma_release_channel(chan);
        return -1;
    }
    tx->callback = test_dma_callback;

    dma_cookie = dmaengine_submit(tx);
    if (dma_submit_error(dma_cookie))
        printk(KERN_ERR "Failed to do DMA tx_submit");

    dma_async_issue_pending(chan);
    wait_event_interruptible_timeout(gdata->wq, gdata->dma_finished, msecs_to_jiffies(1000));

    return 0;
}

static int test_dma_vmap(struct file *fp, void* data)
{
    //struct miscdevice *misc_dev = fp->private_data;
    //struct device *dev = misc_dev->parent;
    struct device *dev = gdata->chan->device->dev;
    struct dma_heap_allocation_data *heap_data = (struct dma_heap_allocation_data *)data;

    int ret = 0;
    int fd  = (int)heap_data->fd;
    struct dma_buf_map ptr;

    printk(KERN_ERR "%s\n",  __func__);
    if ((ret = dma_set_mask(dev, DMA_BIT_MASK(64))) < 0) {
        printk(KERN_ERR "dma set mask failed:%d\n", ret);
        return -1;
    }

    gdata->dma_buf  = dma_buf_get(fd);
    if (IS_ERR(gdata->dma_buf)) {
        printk(KERN_ERR "test_dma_vmap get dma buf failed\n");
        ret = -1;
        goto fail_dma_buf_get;
    }

    gdata->attachment = dma_buf_attach(gdata->dma_buf, dev);
    if (IS_ERR(gdata->attachment)) {
        ret = -1;
        printk(KERN_ERR "test_dma_vmap dma buf attach failed\n");
        goto fail_dma_buf_attach;
    }

    gdata->sgt = dma_buf_map_attachment(gdata->attachment, DMA_BIDIRECTIONAL);
    if (IS_ERR(gdata->sgt)) {
        printk(KERN_ERR "test_dma_vmap dma_buf_map_attachment fail\n");
        goto fail_dma_buf_map_attachment;
    }

    /* map to kernel and access the mem */
    gdata->buf = dma_buf_vmap(gdata->dma_buf, &ptr);
    if (gdata->buf == NULL) {
        pr_err("test_dma_vmap dma_buf_vmap fail\n");
        goto fail_dma_buf_vmap;
    }
    printk(KERN_ERR "dma buf content:%s\n", gdata->buf);

    gdata->fd = fd;
    gdata->len = sg_dma_len(gdata->sgt->sgl);
    return 0;

fail_dma_buf_vmap:
    dma_buf_unmap_attachment(gdata->attachment, gdata->sgt, DMA_BIDIRECTIONAL);
fail_dma_buf_map_attachment:
    dma_buf_detach(gdata->dma_buf, gdata->attachment);
fail_dma_buf_attach:
    dma_buf_put(gdata->dma_buf);
fail_dma_buf_get:
    return ret;
}

static int test_dma_vunmap(void)
{
    struct dma_buf_map ptr = gdata->dma_buf->vmap_ptr;
    dma_buf_vunmap(gdata->dma_buf, &ptr);
    dma_buf_unmap_attachment(gdata->attachment, gdata->sgt, DMA_BIDIRECTIONAL);
    dma_buf_detach(gdata->dma_buf, gdata->attachment);
    dma_buf_put(gdata->dma_buf);
    return 0;
}

static ssize_t test_dma_write(struct file *fp, const char __user *buf,
            size_t count, loff_t *pos)
{
    return 0;
}

static ssize_t test_dma_read(struct file *fp, char __user *buf,
            size_t count, loff_t *pos)
{
    int ret = 0;

    return ret;
}

static int test_dma_mmap(struct file *filp, struct vm_area_struct *vma)
{
    return 0;
}

static void test_dma_reserve(struct device* dev)
{
    int ret;
    void *addr;
    struct page* page;
    dma_addr_t dma_handle;

    dma_set_coherent_mask(dev, DMA_BIT_MASK(64));
    ret = of_reserved_mem_device_init(dev);
    if (ret && ret != -ENODEV) {
        pr_err("test_dma reserve device memory failed:%d\n", ret);
        return;
    }

    addr = dma_alloc_coherent(dev, 0x100000, &dma_handle, __GFP_DMA32|__GFP_ZERO|GFP_DMA32);
    if (!addr) {
        pr_err("test_dma alloc failed\n");
        return;
    } else {
        strcpy((char *)addr, "test dma");
        pr_err("addr(0x%llx):%s\n", dma_handle, (char*)addr);
        dma_free_coherent(dev, 0x100000, addr, dma_handle);
    }

    page = dma_alloc_contiguous(dev, 0x10000, GFP_KERNEL);
    if (page) {
        pr_err("cma addr:0x%llx",__pfn_to_phys(__page_to_pfn(page)));
        dma_free_contiguous(dev, page, 0x10000);
    } else {
        pr_err("dma_alloc_contiguous failed\n");
    }
}

static long test_dma_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret = 0;
    struct dma_heap_allocation_data heap_data;

    if (_IOC_SIZE(cmd) > sizeof(int))
        return -EINVAL;

    switch (cmd) {
        case TEST_DMA_INIT_DMA:
            test_dma_init_dma();
            break;
        case TEST_DMA_MEMCPY:
            test_dma_memcpy();
            break;
        case TEST_DMA_RELEASE_DMA:
            test_dma_release_dma();
            break;
        case TEST_DMA_VMAP:
            if (copy_from_user(&heap_data, (void __user *)arg,
                        sizeof(struct dma_heap_allocation_data))) {
                printk(KERN_ERR "test_dma_vmap copy_from_user fail\n");
                return -1;
            }
            test_dma_vmap(filp, &heap_data);
            break;
        case TEST_DMA_VUNMAP:
            test_dma_vunmap();
            break;
        case TEST_DMA_RESERVE_MEM:
            test_dma_reserve(gdata->misc_parent);
            break;
        default:
            break;
    }

    return ret;
}

static int test_dma_release(struct inode *ip, struct file *fp)
{
    printk(KERN_ERR "%s\n", __func__);

    return 0;
}

static int test_dma_open(struct inode *ip, struct file *fp)
{
    printk(KERN_ERR "%s\n", __func__);
    fp->private_data = gdata;

    return 0;
}

static const struct file_operations test_dma_fops = {
    .owner    = THIS_MODULE,
    .read     = test_dma_read,
    .write    = test_dma_write,
    .open     = test_dma_open,
    .mmap      = test_dma_mmap,
    .unlocked_ioctl = test_dma_ioctl,
    .release  = test_dma_release,
};

static struct miscdevice miscdev = {
    .minor    = MISC_DYNAMIC_MINOR,
    .name     = "test_dma",
    .fops     = &test_dma_fops,
};


static int test_dma_probe(struct platform_device *pdev)
{
    int ret = 0;

    printk(KERN_ERR "%s\n", __func__);
    ret = misc_register(&miscdev);
    if (ret) {
        printk("misc_register failed\n");
        goto fail_miscreg;
    }

    miscdev.parent = &pdev->dev;

    if (pdev->dev.of_node == NULL) {
        printk(KERN_ERR "no of node\n");
        ret = -1;
        goto fail_check_node;
    }

    gdata = (struct testdma_t *)kmalloc(sizeof(struct testdma_t), GFP_KERNEL);
    if (!gdata) {
        printk(KERN_ERR "no memory");
        ret = -ENOMEM;
        goto fail_nomem;
    }

    mutex_init(&gdata->mutex);
    init_waitqueue_head(&gdata->wq);
    gdata->misc_parent = miscdev.parent;

    return 0;

fail_nomem:
fail_check_node:
    misc_deregister(&miscdev);
fail_miscreg:

    return ret;
}

static int test_dma_remove(struct platform_device *pdev)
{
    misc_deregister(&miscdev);
    mutex_destroy(&gdata->mutex);
    if (gdata) {
        kfree(gdata);
    }
    return 0;
}

static const struct of_device_id test_dma_of_match[] = {
    { .compatible = "xring,dma_test" },
    {}
};

MODULE_DEVICE_TABLE(of, test_dma_of_match);

static struct platform_driver test_dma_platform_driver = {
    .probe = test_dma_probe,
    .remove = test_dma_remove,
    .driver = {
        .name = "xring,dma_test",
        .of_match_table = test_dma_of_match,
    },
};

#ifndef TEST_DMA_MODULE
static int __init test_dma_init(void)
{
    printk(KERN_ERR "%s!\n", __func__);
    platform_driver_register(&test_dma_platform_driver);
    return 0;
}

static void __exit test_dma_exit(void)
{
    printk(KERN_ERR "%s\n", __func__);
    platform_driver_unregister(&test_dma_platform_driver);
}

module_init(test_dma_init);
module_exit(test_dma_exit);
#else
module_platform_driver(test_dma_platform_driver);
#endif
MODULE_AUTHOR("zhanglin3406@gmail.com");
MODULE_LICENSE("GPL");
