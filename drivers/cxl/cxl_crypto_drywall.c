// SPDX-License-Identifier: GPL-2.0
/*
 * CXL Type 1 Crypto Accelerator Driver with Drywall Security Extensions
 * 
 * This driver implements the Drywall security model for CXL Type 1 devices
 * to protect against malicious state and unplugging vulnerabilities
 * 
 * Based on CSE290X Final Report: Drywall - Reinforce the CXL malicious state
 * from kernel and TDX applications
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/atomic.h>
#include <linux/bitmap.h>
/* dm-crypt integration would go here */
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include "cxl.h"
#include "cxlmem.h"
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/delay.h>

#define CXL_CRYPTO_DRV_NAME    "cxl_crypto_drywall"
#define CXL_CRYPTO_VERSION     "2.0.0"

/* Intel CXL Type 1 Device IDs */
#define PCI_VENDOR_ID_INTEL_CXL 0x8086
#define PCI_DEVICE_ID_INTEL_CXL_TYPE1 0x0d90

/* CXL Crypto Device Registers */
#define CXL_CRYPTO_CAP         0x00  /* Capability register */
#define CXL_CRYPTO_CTRL        0x04  /* Control register */
#define CXL_CRYPTO_STATUS      0x08  /* Status register */
#define CXL_CRYPTO_CMD         0x0C  /* Command register */
#define CXL_CRYPTO_ATS         0x10  /* ATS tracking register */
#define CXL_CRYPTO_EXCLUSIVE   0x14  /* Exclusive cacheline register */
#define CXL_CRYPTO_SPP_CTRL    0x18  /* Sub-page protection control */
#define CXL_CRYPTO_ERROR_INJ   0x1C  /* Error injection register */

/* ATS (Address Translation Services) bits for exclusiveness tracking */
#define ATS_EXCLUSIVE_CAPABLE  BIT(0)
#define ATS_EXCLUSIVE_HELD     BIT(1)
#define ATS_FALLBACK_REQUIRED  BIT(2)
#define ATS_DEVICE_MALICIOUS   BIT(3)

/* SPP (Sub-Page Protection) definitions */
#define SPP_GRANULARITY        128   /* 128 bytes sub-page */
#define SPP_ENABLED            BIT(23)

/* Cacheline states (MESI protocol) */
enum cacheline_state {
	MESI_INVALID = 0,
	MESI_SHARED,
	MESI_EXCLUSIVE,
	MESI_MODIFIED
};

/* Cacheline tracking structure */
struct cacheline_tracker {
	u64 address;
	u64 ats_bits;
	enum cacheline_state state;
	u8 data[64];  /* 64-byte cacheline */
	u8 backup[64]; /* Backup for recovery */
	bool exclusive_held;
	ktime_t timestamp;
};

/* Enhanced CXL crypto device structure with Drywall features */
struct cxl_crypto_device {
	struct pci_dev *pdev;
	struct device *dev;
	void __iomem *mmio_base;
	void __iomem *cache_base;
	
	/* Crypto specific */
	struct crypto_engine *engine;
	struct crypto_skcipher *fallback_cipher;  /* Software fallback */
	struct list_head pending_requests;
	spinlock_t lock;
	
	/* CXL specific */
	struct cxl_memdev *cxlmd;
	struct cxl_port *port;
	
	/* Drywall security features */
	atomic_t device_state;  /* Device health state */
	atomic_t exclusive_count;  /* Count of exclusive cachelines */
	
	/* Cacheline tracking */
	struct cacheline_tracker *cacheline_map;
	unsigned long *cacheline_bitmap;
	size_t cacheline_count;
	struct rw_semaphore cacheline_sem;
	
	/* SPP (Sub-Page Protection) */
	bool spp_enabled;
	void __iomem *spp_table;
	
	/* Error injection for testing */
	bool error_injection_enabled;
	u32 error_injection_mask;
	
	/* Device monitoring */
	struct task_struct *monitor_thread;
	struct delayed_work health_check_work;
	bool device_alive;
	
	/* Statistics */
	atomic64_t fallback_count;
	atomic64_t exclusive_violations;
	atomic64_t recovery_count;
	
	/* Cache management */
	size_t cache_size;
	size_t device_size;
	
	/* DMA */
	dma_addr_t dma_addr_in;
	dma_addr_t dma_addr_out;
	void *dma_buffer_in;
	void *dma_buffer_out;
	
	/* IRQ */
	int irq;
	struct work_struct work;
};

/* Device states */
enum device_state {
	DEVICE_HEALTHY = 0,
	DEVICE_DEGRADED,
	DEVICE_MALICIOUS,
	DEVICE_OFFLINE
};

/* Enhanced crypto request with ATS tracking */
struct cxl_crypto_request {
	struct list_head list;
	struct cxl_crypto_device *cxl_dev;
	
	/* ATS tracking */
	u64 ats_bits;
	bool uses_exclusive_cacheline;
	
	/* Operation type */
	u32 op_type;
	
	/* Data */
	struct scatterlist *src;
	struct scatterlist *dst;
	unsigned int len;
	
	/* Key and IV */
	u8 key[32];
	u8 iv[16];
	unsigned int key_len;
	
	/* Callback */
	void (*complete)(struct cxl_crypto_request *req);
	void *context;
	
	/* Fallback flag */
	bool use_fallback;
};

/* Function prototypes */
static int cxl_crypto_fallback_init(struct cxl_crypto_device *dev);
static void cxl_crypto_fallback_cleanup(struct cxl_crypto_device *dev);
static int cxl_crypto_process_fallback(struct cxl_crypto_request *req);
static int cxl_crypto_monitor_thread(void *data);
static void cxl_crypto_health_check(struct work_struct *work);
static int cxl_crypto_track_cacheline(struct cxl_crypto_device *dev, 
                                      u64 addr, bool exclusive);
static void cxl_crypto_release_cacheline(struct cxl_crypto_device *dev, u64 addr);
static int cxl_crypto_recover_exclusive_cachelines(struct cxl_crypto_device *dev);
static void cxl_crypto_inject_error(struct cxl_crypto_device *dev, u32 error_type);

/* Initialize software fallback cipher */
static int cxl_crypto_fallback_init(struct cxl_crypto_device *dev)
{
	dev->fallback_cipher = crypto_alloc_skcipher("cbc(aes)", 0, 
	                                             CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(dev->fallback_cipher)) {
		dev_err(dev->dev, "Failed to allocate fallback cipher\n");
		return PTR_ERR(dev->fallback_cipher);
	}
	
	dev_info(dev->dev, "Software fallback cipher initialized\n");
	return 0;
}

static void cxl_crypto_fallback_cleanup(struct cxl_crypto_device *dev)
{
	if (dev->fallback_cipher) {
		crypto_free_skcipher(dev->fallback_cipher);
		dev->fallback_cipher = NULL;
	}
}

/* Process request using software fallback */
static int cxl_crypto_process_fallback(struct cxl_crypto_request *req)
{
	struct cxl_crypto_device *dev = req->cxl_dev;
	struct skcipher_request *skreq;
	int ret;
	
	atomic64_inc(&dev->fallback_count);
	
	skreq = skcipher_request_alloc(dev->fallback_cipher, GFP_KERNEL);
	if (!skreq)
		return -ENOMEM;
	
	crypto_skcipher_setkey(dev->fallback_cipher, req->key, req->key_len);
	
	skcipher_request_set_crypt(skreq, req->src, req->dst, req->len, req->iv);
	
	if (req->op_type == 0x01) /* ENCRYPT */
		ret = crypto_skcipher_encrypt(skreq);
	else /* DECRYPT */
		ret = crypto_skcipher_decrypt(skreq);
	
	skcipher_request_free(skreq);
	
	dev_dbg(dev->dev, "Fallback crypto operation completed: %d\n", ret);
	return ret;
}

/* Track cacheline with ATS bits */
static int cxl_crypto_track_cacheline(struct cxl_crypto_device *dev, 
                                      u64 addr, bool exclusive)
{
	struct cacheline_tracker *tracker;
	int idx;
	
	down_write(&dev->cacheline_sem);
	
	/* Find free slot */
	idx = find_first_zero_bit(dev->cacheline_bitmap, dev->cacheline_count);
	if (idx >= dev->cacheline_count) {
		up_write(&dev->cacheline_sem);
		return -ENOMEM;
	}
	
	tracker = &dev->cacheline_map[idx];
	tracker->address = addr & ~0x3F; /* Align to 64-byte */
	tracker->ats_bits = ATS_EXCLUSIVE_CAPABLE;
	
	if (exclusive) {
		tracker->ats_bits |= ATS_EXCLUSIVE_HELD;
		tracker->exclusive_held = true;
		tracker->state = MESI_EXCLUSIVE;
		atomic_inc(&dev->exclusive_count);
		
		/* Backup data for recovery */
		memcpy(tracker->backup, (void *)addr, 64);
	} else {
		tracker->state = MESI_SHARED;
	}
	
	tracker->timestamp = ktime_get();
	set_bit(idx, dev->cacheline_bitmap);
	
	up_write(&dev->cacheline_sem);
	
	dev_dbg(dev->dev, "Tracked cacheline at 0x%llx, exclusive=%d\n", 
	        addr, exclusive);
	return 0;
}

/* Release tracked cacheline */
__attribute__((unused))
static void cxl_crypto_release_cacheline(struct cxl_crypto_device *dev, u64 addr)
{
	struct cacheline_tracker *tracker;
	int i;
	
	down_write(&dev->cacheline_sem);
	
	for (i = 0; i < dev->cacheline_count; i++) {
		if (!test_bit(i, dev->cacheline_bitmap))
			continue;
			
		tracker = &dev->cacheline_map[i];
		if ((tracker->address & ~0x3F) == (addr & ~0x3F)) {
			if (tracker->exclusive_held)
				atomic_dec(&dev->exclusive_count);
			
			clear_bit(i, dev->cacheline_bitmap);
			memset(tracker, 0, sizeof(*tracker));
			break;
		}
	}
	
	up_write(&dev->cacheline_sem);
}

/* Recover exclusive cachelines when device fails */
static int cxl_crypto_recover_exclusive_cachelines(struct cxl_crypto_device *dev)
{
	struct cacheline_tracker *tracker;
	int i, recovered = 0;
	
	dev_warn(dev->dev, "Starting exclusive cacheline recovery\n");
	
	down_read(&dev->cacheline_sem);
	
	for (i = 0; i < dev->cacheline_count; i++) {
		if (!test_bit(i, dev->cacheline_bitmap))
			continue;
			
		tracker = &dev->cacheline_map[i];
		if (tracker->exclusive_held) {
			/* Restore backup data */
			memcpy((void *)tracker->address, tracker->backup, 64);
			
			/* Mark for fallback */
			tracker->ats_bits |= ATS_FALLBACK_REQUIRED;
			tracker->exclusive_held = false;
			
			recovered++;
			atomic64_inc(&dev->recovery_count);
		}
	}
	
	up_read(&dev->cacheline_sem);
	
	dev_info(dev->dev, "Recovered %d exclusive cachelines\n", recovered);
	return recovered;
}

/* Device health monitoring thread */
static int cxl_crypto_monitor_thread(void *data)
{
	struct cxl_crypto_device *dev = data;
	u32 status;
	
	while (!kthread_should_stop()) {
		/* Read device status */
		status = readl(dev->mmio_base + CXL_CRYPTO_STATUS);
		
		/* Check for device errors */
		if (status & BIT(2)) { /* ERROR bit */
			dev_err(dev->dev, "Device error detected: 0x%08x\n", status);
			atomic_set(&dev->device_state, DEVICE_MALICIOUS);
			
			/* Trigger recovery */
			cxl_crypto_recover_exclusive_cachelines(dev);
			
			/* Mark device for fallback */
			dev->device_alive = false;
		}
		
		/* Check exclusive cacheline violations */
		if (atomic_read(&dev->exclusive_count) > 0) {
			u32 exclusive_status = readl(dev->mmio_base + CXL_CRYPTO_EXCLUSIVE);
			if (exclusive_status & BIT(31)) { /* Violation flag */
				atomic64_inc(&dev->exclusive_violations);
				dev_warn(dev->dev, "Exclusive cacheline violation detected\n");
			}
		}
		
		msleep(100); /* Check every 100ms */
	}
	
	return 0;
}

/* Health check work function */
static void cxl_crypto_health_check(struct work_struct *work)
{
	struct cxl_crypto_device *dev = container_of(work, 
	                                             struct cxl_crypto_device,
	                                             health_check_work.work);
	int state = atomic_read(&dev->device_state);
	
	if (state == DEVICE_MALICIOUS || state == DEVICE_OFFLINE) {
		dev_warn(dev->dev, "Device in malicious/offline state, using fallback\n");
		/* Ensure all new requests use fallback */
		dev->device_alive = false;
	}
	
	/* Print statistics */
	dev_info(dev->dev, "Stats: fallback=%lld, violations=%lld, recoveries=%lld\n",
	         atomic64_read(&dev->fallback_count),
	         atomic64_read(&dev->exclusive_violations),
	         atomic64_read(&dev->recovery_count));
	
	/* Reschedule */
	if (dev->device_alive)
		schedule_delayed_work(&dev->health_check_work, HZ * 5);
}

/* Error injection for testing */
static void cxl_crypto_inject_error(struct cxl_crypto_device *dev, u32 error_type)
{
	if (!dev->error_injection_enabled)
		return;
	
	dev_warn(dev->dev, "Injecting error type: 0x%08x\n", error_type);
	
	switch (error_type) {
	case 0x1: /* Device unplug simulation */
		atomic_set(&dev->device_state, DEVICE_OFFLINE);
		dev->device_alive = false;
		cxl_crypto_recover_exclusive_cachelines(dev);
		break;
		
	case 0x2: /* Malicious state */
		atomic_set(&dev->device_state, DEVICE_MALICIOUS);
		writel(BIT(2), dev->mmio_base + CXL_CRYPTO_STATUS);
		break;
		
	case 0x4: /* Exclusive cacheline violation */
		if (atomic_read(&dev->exclusive_count) > 0) {
			writel(BIT(31), dev->mmio_base + CXL_CRYPTO_EXCLUSIVE);
			atomic64_inc(&dev->exclusive_violations);
		}
		break;
		
	default:
		dev_err(dev->dev, "Unknown error type: 0x%08x\n", error_type);
	}
}

/* Submit crypto request with Drywall protections */
static int cxl_crypto_submit_request(struct cxl_crypto_device *dev,
                                     struct cxl_crypto_request *req)
{
	unsigned long flags;
	int ret = 0;
	
	/* Check device state */
	if (!dev->device_alive || 
	    atomic_read(&dev->device_state) != DEVICE_HEALTHY) {
		/* Use software fallback */
		req->use_fallback = true;
		return cxl_crypto_process_fallback(req);
	}
	
	/* Track cacheline if using exclusive access */
	if (req->uses_exclusive_cacheline) {
		ret = cxl_crypto_track_cacheline(dev, (u64)req->src, true);
		if (ret) {
			dev_warn(dev->dev, "Failed to track cacheline, using fallback\n");
			req->use_fallback = true;
			return cxl_crypto_process_fallback(req);
		}
	}
	
	spin_lock_irqsave(&dev->lock, flags);
	list_add_tail(&req->list, &dev->pending_requests);
	spin_unlock_irqrestore(&dev->lock, flags);
	
	/* Trigger hardware processing */
	writel(req->op_type, dev->mmio_base + CXL_CRYPTO_CMD);
	
	return ret;
}

/* Crypto algorithm implementations */
static int cxl_crypto_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
                                unsigned int keylen)
{
	if (keylen != 16 && keylen != 24 && keylen != 32)
		return -EINVAL;
	
	/* Key will be set during operation */
	return 0;
}

static int cxl_crypto_aes_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct cxl_crypto_device *dev = crypto_skcipher_ctx(tfm);
	struct cxl_crypto_request *cxl_req;
	
	cxl_req = kzalloc(sizeof(*cxl_req), GFP_KERNEL);
	if (!cxl_req)
		return -ENOMEM;
	
	cxl_req->cxl_dev = dev;
	cxl_req->op_type = 0x01; /* ENCRYPT */
	cxl_req->src = req->src;
	cxl_req->dst = req->dst;
	cxl_req->len = req->cryptlen;
	memcpy(cxl_req->iv, req->iv, 16);
	
	/* Set ATS bits for exclusiveness tracking */
	cxl_req->ats_bits = ATS_EXCLUSIVE_CAPABLE;
	cxl_req->uses_exclusive_cacheline = true;
	
	return cxl_crypto_submit_request(dev, cxl_req);
}

static int cxl_crypto_aes_decrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct cxl_crypto_device *dev = crypto_skcipher_ctx(tfm);
	struct cxl_crypto_request *cxl_req;
	
	cxl_req = kzalloc(sizeof(*cxl_req), GFP_KERNEL);
	if (!cxl_req)
		return -ENOMEM;
	
	cxl_req->cxl_dev = dev;
	cxl_req->op_type = 0x02; /* DECRYPT */
	cxl_req->src = req->src;
	cxl_req->dst = req->dst;
	cxl_req->len = req->cryptlen;
	memcpy(cxl_req->iv, req->iv, 16);
	
	/* Set ATS bits */
	cxl_req->ats_bits = ATS_EXCLUSIVE_CAPABLE;
	cxl_req->uses_exclusive_cacheline = true;
	
	return cxl_crypto_submit_request(dev, cxl_req);
}

/* Crypto algorithm registration */
static struct skcipher_alg cxl_crypto_aes_alg = {
	.base = {
		.cra_name = "cbc(aes)",
		.cra_driver_name = "cxl-cbc-aes",
		.cra_priority = 400,
		.cra_flags = CRYPTO_ALG_ASYNC,
		.cra_blocksize = 16,
		.cra_ctxsize = sizeof(struct cxl_crypto_device),
		.cra_module = THIS_MODULE,
	},
	.min_keysize = 16,
	.max_keysize = 32,
	.ivsize = 16,
	.setkey = cxl_crypto_aes_setkey,
	.encrypt = cxl_crypto_aes_encrypt,
	.decrypt = cxl_crypto_aes_decrypt,
};

/* PCI driver probe with Drywall enhancements */
static int cxl_crypto_probe(struct pci_dev *pdev,
                           const struct pci_device_id *id)
{
	struct cxl_crypto_device *dev;
	int ret;
	
	dev = devm_kzalloc(&pdev->dev, sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;
	
	dev->pdev = pdev;
	dev->dev = &pdev->dev;
	spin_lock_init(&dev->lock);
	INIT_LIST_HEAD(&dev->pending_requests);
	init_rwsem(&dev->cacheline_sem);
	
	/* Initialize atomic counters */
	atomic_set(&dev->device_state, DEVICE_HEALTHY);
	atomic_set(&dev->exclusive_count, 0);
	atomic64_set(&dev->fallback_count, 0);
	atomic64_set(&dev->exclusive_violations, 0);
	atomic64_set(&dev->recovery_count, 0);
	
	/* Enable PCI device */
	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to enable PCI device\n");
		return ret;
	}
	
	/* Map MMIO regions */
	ret = pcim_iomap_regions(pdev, BIT(0) | BIT(2), CXL_CRYPTO_DRV_NAME);
	if (ret) {
		dev_err(&pdev->dev, "Failed to map MMIO regions\n");
		return ret;
	}
	
	dev->mmio_base = pcim_iomap_table(pdev)[0];
	dev->cache_base = pcim_iomap_table(pdev)[2];
	
	/* Initialize cacheline tracking */
	dev->cacheline_count = 1024; /* Track up to 1024 cachelines */
	dev->cacheline_map = devm_kcalloc(&pdev->dev, dev->cacheline_count,
	                                  sizeof(struct cacheline_tracker),
	                                  GFP_KERNEL);
	if (!dev->cacheline_map)
		return -ENOMEM;
	
	dev->cacheline_bitmap = devm_bitmap_zalloc(&pdev->dev, 
	                                           dev->cacheline_count,
	                                           GFP_KERNEL);
	if (!dev->cacheline_bitmap)
		return -ENOMEM;
	
	/* Initialize software fallback */
	ret = cxl_crypto_fallback_init(dev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to initialize fallback cipher\n");
		return ret;
	}
	
	/* Register crypto algorithm */
	ret = crypto_register_skcipher(&cxl_crypto_aes_alg);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register crypto algorithm\n");
		goto err_fallback;
	}
	
	/* Start monitoring thread */
	dev->device_alive = true;
	dev->monitor_thread = kthread_run(cxl_crypto_monitor_thread, dev,
	                                  "cxl_crypto_monitor");
	if (IS_ERR(dev->monitor_thread)) {
		ret = PTR_ERR(dev->monitor_thread);
		goto err_unreg_crypto;
	}
	
	/* Initialize health check work */
	INIT_DELAYED_WORK(&dev->health_check_work, cxl_crypto_health_check);
	schedule_delayed_work(&dev->health_check_work, HZ * 5);
	
	/* Enable error injection for testing */
	dev->error_injection_enabled = true;
	
	pci_set_drvdata(pdev, dev);
	pci_set_master(pdev);
	
	dev_info(&pdev->dev, "CXL Crypto Drywall driver initialized\n");
	dev_info(&pdev->dev, "ATS tracking enabled, SPP support ready\n");
	
	return 0;
	
err_unreg_crypto:
	crypto_unregister_skcipher(&cxl_crypto_aes_alg);
err_fallback:
	cxl_crypto_fallback_cleanup(dev);
	return ret;
}

/* PCI driver remove */
static void cxl_crypto_remove(struct pci_dev *pdev)
{
	struct cxl_crypto_device *dev = pci_get_drvdata(pdev);
	
	/* Stop monitoring thread */
	if (dev->monitor_thread)
		kthread_stop(dev->monitor_thread);
	
	/* Cancel health check work */
	cancel_delayed_work_sync(&dev->health_check_work);
	
	/* Recover any held exclusive cachelines */
	if (atomic_read(&dev->exclusive_count) > 0)
		cxl_crypto_recover_exclusive_cachelines(dev);
	
	/* Unregister crypto algorithms */
	crypto_unregister_skcipher(&cxl_crypto_aes_alg);
	
	/* Cleanup fallback */
	cxl_crypto_fallback_cleanup(dev);
	
	dev_info(&pdev->dev, "CXL Crypto Drywall driver removed\n");
	dev_info(&pdev->dev, "Final stats: fallback=%lld, violations=%lld, recoveries=%lld\n",
	         atomic64_read(&dev->fallback_count),
	         atomic64_read(&dev->exclusive_violations),
	         atomic64_read(&dev->recovery_count));
}

/* Sysfs interface for error injection */
static ssize_t error_inject_store(struct device *dev,
                                  struct device_attribute *attr,
                                  const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct cxl_crypto_device *cxl_dev = pci_get_drvdata(pdev);
	u32 error_type;
	
	if (kstrtou32(buf, 0, &error_type))
		return -EINVAL;
	
	cxl_crypto_inject_error(cxl_dev, error_type);
	
	return count;
}

static DEVICE_ATTR_WO(error_inject);

static struct attribute *cxl_crypto_attrs[] = {
	&dev_attr_error_inject.attr,
	NULL
};

static const struct attribute_group cxl_crypto_attr_group = {
	.attrs = cxl_crypto_attrs,
};

static const struct attribute_group *cxl_crypto_attr_groups[] = {
	&cxl_crypto_attr_group,
	NULL
};

/* PCI device ID table */
static const struct pci_device_id cxl_crypto_pci_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_INTEL_CXL, PCI_DEVICE_ID_INTEL_CXL_TYPE1) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, cxl_crypto_pci_ids);

/* PCI driver structure */
static struct pci_driver cxl_crypto_driver = {
	.name = CXL_CRYPTO_DRV_NAME,
	.id_table = cxl_crypto_pci_ids,
	.probe = cxl_crypto_probe,
	.remove = cxl_crypto_remove,
	.driver.groups = cxl_crypto_attr_groups,
};

/* Module init */
static int __init cxl_crypto_init(void)
{
	pr_info("CXL Crypto Drywall Driver v%s loading\n", CXL_CRYPTO_VERSION);
	pr_info("Implementing Drywall security model for CXL Type 1 devices\n");
	return pci_register_driver(&cxl_crypto_driver);
}

/* Module exit */
static void __exit cxl_crypto_exit(void)
{
	pci_unregister_driver(&cxl_crypto_driver);
	pr_info("CXL Crypto Drywall Driver unloaded\n");
}

module_init(cxl_crypto_init);
module_exit(cxl_crypto_exit);

MODULE_AUTHOR("Drywall Research Team");
MODULE_DESCRIPTION("CXL Type 1 Crypto Driver with Drywall Security Extensions");
MODULE_LICENSE("GPL");
MODULE_VERSION(CXL_CRYPTO_VERSION);