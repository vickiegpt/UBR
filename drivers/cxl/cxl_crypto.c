// SPDX-License-Identifier: GPL-2.0
/*
 * CXL Type 1 Crypto Accelerator Driver
 * 
 * This driver provides crypto acceleration services using CXL Type 1 devices
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include "cxl.h"
#include "cxlmem.h"
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/io.h>

#define CXL_CRYPTO_DRV_NAME    "cxl_crypto"
#define CXL_CRYPTO_VERSION     "1.0.0"

/* Intel CXL Type 1 Device IDs */
#define PCI_VENDOR_ID_INTEL_CXL 0x8086
#define PCI_DEVICE_ID_INTEL_CXL_TYPE1 0x0d90

/* CXL Crypto Device Registers */
#define CXL_CRYPTO_CAP         0x00  /* Capability register */
#define CXL_CRYPTO_CTRL        0x04  /* Control register */
#define CXL_CRYPTO_STATUS      0x08  /* Status register */
#define CXL_CRYPTO_CMD         0x0C  /* Command register */
#define CXL_CRYPTO_DATA_IN     0x10  /* Data input register */
#define CXL_CRYPTO_DATA_OUT    0x14  /* Data output register */
#define CXL_CRYPTO_KEY         0x20  /* Key register base */
#define CXL_CRYPTO_IV          0x40  /* IV register base */

/* Crypto operations */
#define CXL_CRYPTO_OP_ENCRYPT  0x01
#define CXL_CRYPTO_OP_DECRYPT  0x02
#define CXL_CRYPTO_OP_HASH     0x04
#define CXL_CRYPTO_OP_MAC      0x08

/* Status bits */
#define CXL_CRYPTO_STATUS_BUSY    BIT(0)
#define CXL_CRYPTO_STATUS_DONE    BIT(1)
#define CXL_CRYPTO_STATUS_ERROR   BIT(2)

struct cxl_crypto_device {
	struct pci_dev *pdev;
	struct device *dev;
	void __iomem *mmio_base;
	void __iomem *cache_base;
	
	/* Crypto specific */
	struct crypto_engine *engine;
	struct list_head pending_requests;
	spinlock_t lock;
	
	/* CXL specific */
	struct cxl_memdev *cxlmd;
	struct cxl_port *port;
	
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

struct cxl_crypto_request {
	struct list_head list;
	struct cxl_crypto_device *cxl_dev;
	
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
};

/* Helper functions to access device registers */
static inline u32 cxl_crypto_read32(struct cxl_crypto_device *dev, u32 reg)
{
	return readl(dev->mmio_base + reg);
}

static inline void cxl_crypto_write32(struct cxl_crypto_device *dev, u32 reg, u32 val)
{
	writel(val, dev->mmio_base + reg);
}

/* Cache operations using CXL Type 1 cache coherency */
static int cxl_crypto_cache_write(struct cxl_crypto_device *dev, 
                                  u64 offset, void *data, size_t len)
{
	if (offset + len > dev->cache_size) {
		dev_err(dev->dev, "Cache write out of bounds: offset=%llu len=%zu\n",
		        offset, len);
		return -EINVAL;
	}
	
	/* Write to cache-coherent region */
	memcpy_toio(dev->cache_base + offset, data, len);
	
	/* Ensure cache coherency */
	wmb();
	
	return 0;
}

static int cxl_crypto_cache_read(struct cxl_crypto_device *dev,
                                 u64 offset, void *data, size_t len)
{
	if (offset + len > dev->cache_size) {
		dev_err(dev->dev, "Cache read out of bounds: offset=%llu len=%zu\n",
		        offset, len);
		return -EINVAL;
	}
	
	/* Read from cache-coherent region */
	memcpy_fromio(data, dev->cache_base + offset, len);
	
	/* Ensure cache coherency */
	rmb();
	
	return 0;
}

/* Submit crypto operation to hardware */
static int cxl_crypto_submit_request(struct cxl_crypto_device *dev,
                                     struct cxl_crypto_request *req)
{
	unsigned long flags;
	u32 status;
	int ret = 0;
	
	spin_lock_irqsave(&dev->lock, flags);
	
	/* Check if device is busy */
	status = cxl_crypto_read32(dev, CXL_CRYPTO_STATUS);
	if (status & CXL_CRYPTO_STATUS_BUSY) {
		/* Add to pending queue */
		list_add_tail(&req->list, &dev->pending_requests);
		spin_unlock_irqrestore(&dev->lock, flags);
		return 0;
	}
	
	/* Copy data to device using cache */
	if (req->src) {
		sg_copy_to_buffer(req->src, sg_nents(req->src),
		                  dev->dma_buffer_in, req->len);
		ret = cxl_crypto_cache_write(dev, 0, dev->dma_buffer_in, req->len);
		if (ret)
			goto out;
	}
	
	/* Set up key */
	if (req->key_len) {
		ret = cxl_crypto_cache_write(dev, dev->cache_size / 2,
		                             req->key, req->key_len);
		if (ret)
			goto out;
	}
	
	/* Set up IV if needed */
	if (req->op_type == CXL_CRYPTO_OP_ENCRYPT ||
	    req->op_type == CXL_CRYPTO_OP_DECRYPT) {
		ret = cxl_crypto_cache_write(dev, dev->cache_size / 2 + 256,
		                             req->iv, 16);
		if (ret)
			goto out;
	}
	
	/* Issue command */
	cxl_crypto_write32(dev, CXL_CRYPTO_CMD, req->op_type);
	cxl_crypto_write32(dev, CXL_CRYPTO_CTRL, req->len);
	
	/* Start operation */
	cxl_crypto_write32(dev, CXL_CRYPTO_STATUS, CXL_CRYPTO_STATUS_BUSY);
	
out:
	spin_unlock_irqrestore(&dev->lock, flags);
	return ret;
}

/* IRQ handler */
static irqreturn_t cxl_crypto_irq_handler(int irq, void *data)
{
	struct cxl_crypto_device *dev = data;
	u32 status;
	
	status = cxl_crypto_read32(dev, CXL_CRYPTO_STATUS);
	
	if (status & CXL_CRYPTO_STATUS_DONE) {
		/* Clear status */
		cxl_crypto_write32(dev, CXL_CRYPTO_STATUS, CXL_CRYPTO_STATUS_DONE);
		
		/* Schedule work to handle completion */
		schedule_work(&dev->work);
		
		return IRQ_HANDLED;
	}
	
	return IRQ_NONE;
}

/* Work handler for crypto completion */
static void cxl_crypto_work_handler(struct work_struct *work)
{
	struct cxl_crypto_device *dev = container_of(work,
	                                             struct cxl_crypto_device,
	                                             work);
	struct cxl_crypto_request *req, *next;
	unsigned long flags;
	
	spin_lock_irqsave(&dev->lock, flags);
	
	/* Process completed requests */
	list_for_each_entry_safe(req, next, &dev->pending_requests, list) {
		/* Read result from cache */
		cxl_crypto_cache_read(dev, 0, dev->dma_buffer_out, req->len);
		
		/* Copy to destination */
		if (req->dst) {
			sg_copy_from_buffer(req->dst, sg_nents(req->dst),
			                   dev->dma_buffer_out, req->len);
		}
		
		/* Remove from list */
		list_del(&req->list);
		
		/* Call completion handler */
		if (req->complete)
			req->complete(req);
		
		break; /* Process one at a time */
	}
	
	/* Submit next request if any */
	if (!list_empty(&dev->pending_requests)) {
		req = list_first_entry(&dev->pending_requests,
		                       struct cxl_crypto_request, list);
		list_del(&req->list);
		spin_unlock_irqrestore(&dev->lock, flags);
		cxl_crypto_submit_request(dev, req);
	} else {
		spin_unlock_irqrestore(&dev->lock, flags);
	}
}

/* Crypto algorithm implementations */
static int cxl_crypto_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
                                unsigned int keylen)
{
	/* struct cxl_crypto_device *dev = crypto_skcipher_ctx(tfm); */
	
	if (keylen != 16 && keylen != 24 && keylen != 32) {
		/* In newer kernels, just return error */
		return -EINVAL;
	}
	
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
	cxl_req->op_type = CXL_CRYPTO_OP_ENCRYPT;
	cxl_req->src = req->src;
	cxl_req->dst = req->dst;
	cxl_req->len = req->cryptlen;
	memcpy(cxl_req->iv, req->iv, 16);
	
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
	cxl_req->op_type = CXL_CRYPTO_OP_DECRYPT;
	cxl_req->src = req->src;
	cxl_req->dst = req->dst;
	cxl_req->len = req->cryptlen;
	memcpy(cxl_req->iv, req->iv, 16);
	
	return cxl_crypto_submit_request(dev, cxl_req);
}

static struct skcipher_alg cxl_crypto_aes_alg = {
	.base = {
		.cra_name = "cbc(aes)",
		.cra_driver_name = "cxl-cbc-aes",
		.cra_priority = 300,
		.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
		.cra_blocksize = 16,
		.cra_ctxsize = sizeof(struct cxl_crypto_device *),
		.cra_module = THIS_MODULE,
	},
	.min_keysize = 16,
	.max_keysize = 32,
	.ivsize = 16,
	.setkey = cxl_crypto_aes_setkey,
	.encrypt = cxl_crypto_aes_encrypt,
	.decrypt = cxl_crypto_aes_decrypt,
};

/* PCI driver probe function */
static int cxl_crypto_probe(struct pci_dev *pdev,
                           const struct pci_device_id *id)
{
	struct cxl_crypto_device *dev;
	int ret;
	
	dev_info(&pdev->dev, "CXL Crypto device found\n");
	
	dev = devm_kzalloc(&pdev->dev, sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;
	
	dev->pdev = pdev;
	dev->dev = &pdev->dev;
	spin_lock_init(&dev->lock);
	INIT_LIST_HEAD(&dev->pending_requests);
	INIT_WORK(&dev->work, cxl_crypto_work_handler);
	
	/* Enable PCI device */
	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to enable PCI device\n");
		return ret;
	}
	
	/* Request PCI regions */
	ret = pcim_iomap_regions(pdev, BIT(0) | BIT(2), CXL_CRYPTO_DRV_NAME);
	if (ret) {
		dev_err(&pdev->dev, "Failed to request PCI regions\n");
		return ret;
	}
	
	/* Map MMIO registers */
	dev->mmio_base = pcim_iomap_table(pdev)[0];
	dev->cache_base = pcim_iomap_table(pdev)[2];
	
	if (!dev->mmio_base || !dev->cache_base) {
		dev_err(&pdev->dev, "Failed to map device registers\n");
		return -ENOMEM;
	}
	
	/* Get cache and device sizes from configuration */
	dev->cache_size = 64 * 1024 * 1024;  /* 64MB default */
	dev->device_size = 256 * 1024 * 1024; /* 256MB default */
	
	/* Set up DMA */
	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(&pdev->dev, "Failed to set DMA mask\n");
		return ret;
	}
	
	/* Allocate DMA buffers */
	dev->dma_buffer_in = dmam_alloc_coherent(&pdev->dev, PAGE_SIZE,
	                                         &dev->dma_addr_in, GFP_KERNEL);
	dev->dma_buffer_out = dmam_alloc_coherent(&pdev->dev, PAGE_SIZE,
	                                          &dev->dma_addr_out, GFP_KERNEL);
	
	if (!dev->dma_buffer_in || !dev->dma_buffer_out) {
		dev_err(&pdev->dev, "Failed to allocate DMA buffers\n");
		return -ENOMEM;
	}
	
	/* Request IRQ */
	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSI | PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to allocate IRQ vectors\n");
		return ret;
	}
	
	dev->irq = pci_irq_vector(pdev, 0);
	ret = devm_request_irq(&pdev->dev, dev->irq, cxl_crypto_irq_handler,
	                      0, CXL_CRYPTO_DRV_NAME, dev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to request IRQ\n");
		goto err_free_irq;
	}
	
	/* Register crypto algorithms */
	ret = crypto_register_skcipher(&cxl_crypto_aes_alg);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register crypto algorithm\n");
		goto err_free_irq;
	}
	
	pci_set_drvdata(pdev, dev);
	pci_set_master(pdev);
	
	/* Read device capabilities */
	u32 cap = cxl_crypto_read32(dev, CXL_CRYPTO_CAP);
	dev_info(&pdev->dev, "CXL Crypto device initialized, capabilities: 0x%08x\n", cap);
	dev_info(&pdev->dev, "Cache size: %zu MB, Device size: %zu MB\n",
	         dev->cache_size / (1024 * 1024),
	         dev->device_size / (1024 * 1024));
	
	return 0;
	
err_free_irq:
	pci_free_irq_vectors(pdev);
	return ret;
}

/* PCI driver remove function */
static void cxl_crypto_remove(struct pci_dev *pdev)
{
	struct cxl_crypto_device *dev = pci_get_drvdata(pdev);
	
	/* Unregister crypto algorithms */
	crypto_unregister_skcipher(&cxl_crypto_aes_alg);
	
	/* Cancel any pending work */
	cancel_work_sync(&dev->work);
	
	/* Free IRQ */
	devm_free_irq(&pdev->dev, dev->irq, dev);
	pci_free_irq_vectors(pdev);
	
	dev_info(&pdev->dev, "CXL Crypto device removed\n");
}

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
};

/* Module init */
static int __init cxl_crypto_init(void)
{
	pr_info("CXL Crypto Driver v%s loading\n", CXL_CRYPTO_VERSION);
	return pci_register_driver(&cxl_crypto_driver);
}

/* Module exit */
static void __exit cxl_crypto_exit(void)
{
	pci_unregister_driver(&cxl_crypto_driver);
	pr_info("CXL Crypto Driver unloaded\n");
}

module_init(cxl_crypto_init);
module_exit(cxl_crypto_exit);

MODULE_AUTHOR("CXL Development Team");
MODULE_DESCRIPTION("CXL Type 1 Crypto Accelerator Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(CXL_CRYPTO_VERSION);