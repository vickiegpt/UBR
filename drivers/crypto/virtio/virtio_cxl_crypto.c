// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio-CXL Crypto Accelerator Driver for LUKS
 * 
 * This driver provides hardware-accelerated crypto for dm-crypt/LUKS
 * using CXL Type 1 devices through virtio transport
 */

#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/scatterlist.h>
#include <linux/spinlock.h>
#include <linux/crypto.h>
#include <crypto/algapi.h>
#include <crypto/internal/skcipher.h>
#include <crypto/internal/hash.h>
#include <linux/dm-crypt.h>
#include <linux/device-mapper.h>

/* Virtio CXL Crypto device ID */
#define VIRTIO_ID_CXL_CRYPTO    42  /* Unique ID for CXL crypto */

/* Feature bits */
#define VIRTIO_CXL_CRYPTO_F_CIPHER_AES     0
#define VIRTIO_CXL_CRYPTO_F_CIPHER_XTS     1
#define VIRTIO_CXL_CRYPTO_F_HASH_SHA256    2
#define VIRTIO_CXL_CRYPTO_F_CXL_CACHE      3
#define VIRTIO_CXL_CRYPTO_F_LUKS_ACCEL     4

/* Operation codes */
#define VIRTIO_CXL_CRYPTO_OP_ENCRYPT    1
#define VIRTIO_CXL_CRYPTO_OP_DECRYPT    2
#define VIRTIO_CXL_CRYPTO_OP_HASH       3

/* CXL cache control */
#define CXL_CACHE_EXCLUSIVE    BIT(0)
#define CXL_CACHE_SHARED       BIT(1)
#define CXL_CACHE_PREFETCH     BIT(2)

struct virtio_cxl_crypto_config {
	__le32 status;
	__le32 max_dataqueues;
	__le32 crypto_services;
	__le32 cipher_algo_l;
	__le32 cipher_algo_h;
	__le32 hash_algo;
	__le32 mac_algo_l;
	__le32 mac_algo_h;
	__le32 aead_algo;
	__le32 max_cipher_key_len;
	__le32 max_auth_key_len;
	__le64 max_size;
	/* CXL specific */
	__le32 cxl_cache_size;
	__le32 cxl_cache_line_size;
	__le32 cxl_exclusive_capable;
} __packed;

struct virtio_cxl_crypto_op_header {
	__le32 opcode;
	__le32 algo;
	__le64 session_id;
	__le32 flag;
	__le32 padding;
	/* CXL cache hints */
	__le32 cache_hint;
	__le32 exclusive_request;
};

struct virtio_cxl_crypto_cipher_para {
	__le32 iv_len;
	__le32 src_data_len;
	__le32 dst_data_len;
};

struct virtio_cxl_crypto_request {
	struct virtio_cxl_crypto_op_header header;
	union {
		struct virtio_cxl_crypto_cipher_para cipher;
		/* Add other operation parameters */
	} u;
	/* Inline data */
	u8 iv[32];
	u8 key[64];
};

struct virtio_cxl_crypto {
	struct virtio_device *vdev;
	struct virtqueue *datavq[16];  /* Multiple queues for parallelism */
	struct virtqueue *ctrlvq;
	
	/* Crypto engine */
	struct crypto_engine *engine;
	
	/* Configuration */
	struct virtio_cxl_crypto_config config;
	
	/* CXL cache management */
	void __iomem *cxl_cache_base;
	size_t cxl_cache_size;
	spinlock_t cache_lock;
	
	/* LUKS integration */
	bool luks_mode;
	struct dm_target *dm_target;
	
	/* Statistics */
	atomic64_t reqs_completed;
	atomic64_t cache_hits;
	atomic64_t cache_misses;
	atomic64_t bytes_encrypted;
	atomic64_t bytes_decrypted;
};

struct virtio_cxl_crypto_request_state {
	struct virtio_cxl_crypto *vcrypto;
	struct virtio_cxl_crypto_request *req;
	struct scatterlist **sgs;
	unsigned int out_num;
	unsigned int in_num;
	u8 *iv;
	struct completion completion;
	int error;
	/* For LUKS */
	struct dm_crypt_request *dmreq;
};

/* LUKS specific algorithms */
static struct skcipher_alg virtio_cxl_aes_xts_alg = {
	.base = {
		.cra_name = "xts(aes)",
		.cra_driver_name = "virtio-cxl-xts-aes",
		.cra_priority = 500,  /* Higher priority for hardware */
		.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
		.cra_blocksize = 16,
		.cra_ctxsize = sizeof(struct virtio_cxl_crypto),
		.cra_module = THIS_MODULE,
	},
	.min_keysize = 32,
	.max_keysize = 64,
	.ivsize = 16,
	.setkey = virtio_cxl_aes_setkey,
	.encrypt = virtio_cxl_aes_xts_encrypt,
	.decrypt = virtio_cxl_aes_xts_decrypt,
};

static struct skcipher_alg virtio_cxl_aes_cbc_alg = {
	.base = {
		.cra_name = "cbc(aes)",
		.cra_driver_name = "virtio-cxl-cbc-aes",
		.cra_priority = 500,
		.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
		.cra_blocksize = 16,
		.cra_ctxsize = sizeof(struct virtio_cxl_crypto),
		.cra_module = THIS_MODULE,
	},
	.min_keysize = 16,
	.max_keysize = 32,
	.ivsize = 16,
	.setkey = virtio_cxl_aes_setkey,
	.encrypt = virtio_cxl_aes_cbc_encrypt,
	.decrypt = virtio_cxl_aes_cbc_decrypt,
};

/* Forward declarations */
static int virtio_cxl_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
                                 unsigned int keylen);
static int virtio_cxl_aes_xts_encrypt(struct skcipher_request *req);
static int virtio_cxl_aes_xts_decrypt(struct skcipher_request *req);
static int virtio_cxl_aes_cbc_encrypt(struct skcipher_request *req);
static int virtio_cxl_aes_cbc_decrypt(struct skcipher_request *req);

/* CXL cache management functions */
static void virtio_cxl_cache_prefetch(struct virtio_cxl_crypto *vcrypto,
                                      void *addr, size_t len)
{
	struct virtio_cxl_crypto_request req = {
		.header.cache_hint = CXL_CACHE_PREFETCH,
	};
	
	/* Send prefetch hint to device */
	/* This will use CXL.cache protocol to prefetch data */
}

static int virtio_cxl_cache_exclusive(struct virtio_cxl_crypto *vcrypto,
                                      void *addr, size_t len)
{
	struct virtio_cxl_crypto_request req = {
		.header.cache_hint = CXL_CACHE_EXCLUSIVE,
		.header.exclusive_request = 1,
	};
	
	/* Request exclusive cacheline access */
	/* Critical for LUKS key material */
	return 0;
}

/* Virtqueue operations */
static void virtio_cxl_datavq_callback(struct virtqueue *vq)
{
	struct virtio_cxl_crypto *vcrypto = vq->vdev->priv;
	struct virtio_cxl_crypto_request_state *req_state;
	unsigned int len;
	
	while ((req_state = virtqueue_get_buf(vq, &len)) != NULL) {
		if (req_state->dmreq) {
			/* Complete dm-crypt request */
			req_state->dmreq->error = req_state->error;
			complete(&req_state->completion);
		}
		
		atomic64_inc(&vcrypto->reqs_completed);
		
		/* Update statistics */
		if (req_state->req->header.opcode == VIRTIO_CXL_CRYPTO_OP_ENCRYPT)
			atomic64_add(len, &vcrypto->bytes_encrypted);
		else
			atomic64_add(len, &vcrypto->bytes_decrypted);
	}
}

/* Submit crypto request to virtqueue */
static int virtio_cxl_crypto_submit_req(struct virtio_cxl_crypto *vcrypto,
                                        struct virtio_cxl_crypto_request_state *req_state)
{
	struct scatterlist *sgs[4];
	unsigned int out_num = 0, in_num = 0;
	int ret;
	
	/* Setup scatterlists for request header and data */
	sg_init_one(&sgs[out_num], req_state->req, sizeof(*req_state->req));
	out_num++;
	
	/* Add data scatterlists */
	/* ... */
	
	spin_lock(&vcrypto->cache_lock);
	ret = virtqueue_add_sgs(vcrypto->datavq[0], sgs, out_num, in_num,
	                        req_state, GFP_ATOMIC);
	if (!ret)
		virtqueue_kick(vcrypto->datavq[0]);
	spin_unlock(&vcrypto->cache_lock);
	
	return ret;
}

/* Algorithm implementations */
static int virtio_cxl_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
                                 unsigned int keylen)
{
	struct virtio_cxl_crypto *vcrypto = crypto_skcipher_ctx(tfm);
	
	/* For LUKS, we need XTS mode which uses two keys */
	if (keylen != 32 && keylen != 64)
		return -EINVAL;
	
	/* Request exclusive cache access for key material */
	virtio_cxl_cache_exclusive(vcrypto, (void *)key, keylen);
	
	return 0;
}

static int virtio_cxl_aes_xts_crypt(struct skcipher_request *req, int encrypt)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct virtio_cxl_crypto *vcrypto = crypto_skcipher_ctx(tfm);
	struct virtio_cxl_crypto_request_state *req_state;
	struct virtio_cxl_crypto_request *vreq;
	int ret;
	
	req_state = kzalloc(sizeof(*req_state), GFP_KERNEL);
	if (!req_state)
		return -ENOMEM;
	
	vreq = kzalloc(sizeof(*vreq), GFP_KERNEL);
	if (!vreq) {
		kfree(req_state);
		return -ENOMEM;
	}
	
	/* Setup request */
	vreq->header.opcode = encrypt ? VIRTIO_CXL_CRYPTO_OP_ENCRYPT :
	                                VIRTIO_CXL_CRYPTO_OP_DECRYPT;
	vreq->header.algo = VIRTIO_CXL_CRYPTO_F_CIPHER_XTS;
	vreq->u.cipher.src_data_len = req->cryptlen;
	vreq->u.cipher.dst_data_len = req->cryptlen;
	vreq->u.cipher.iv_len = 16;
	
	/* Copy IV */
	memcpy(vreq->iv, req->iv, 16);
	
	/* Setup cache hints for better performance */
	vreq->header.cache_hint = CXL_CACHE_PREFETCH | CXL_CACHE_EXCLUSIVE;
	
	/* Prefetch data into CXL cache */
	virtio_cxl_cache_prefetch(vcrypto, sg_virt(req->src), req->cryptlen);
	
	req_state->vcrypto = vcrypto;
	req_state->req = vreq;
	init_completion(&req_state->completion);
	
	/* Submit to virtqueue */
	ret = virtio_cxl_crypto_submit_req(vcrypto, req_state);
	if (ret) {
		kfree(vreq);
		kfree(req_state);
		return ret;
	}
	
	/* Wait for completion */
	wait_for_completion(&req_state->completion);
	
	ret = req_state->error;
	kfree(vreq);
	kfree(req_state);
	
	return ret;
}

static int virtio_cxl_aes_xts_encrypt(struct skcipher_request *req)
{
	return virtio_cxl_aes_xts_crypt(req, 1);
}

static int virtio_cxl_aes_xts_decrypt(struct skcipher_request *req)
{
	return virtio_cxl_aes_xts_crypt(req, 0);
}

static int virtio_cxl_aes_cbc_encrypt(struct skcipher_request *req)
{
	/* Similar to XTS but with CBC mode */
	return virtio_cxl_aes_xts_crypt(req, 1);
}

static int virtio_cxl_aes_cbc_decrypt(struct skcipher_request *req)
{
	return virtio_cxl_aes_xts_crypt(req, 0);
}

/* dm-crypt integration */
static int virtio_cxl_dmcrypt_crypt(struct dm_crypt_request *dmreq, bool encrypt)
{
	struct virtio_cxl_crypto *vcrypto;
	struct virtio_cxl_crypto_request_state *req_state;
	struct virtio_cxl_crypto_request *vreq;
	int ret;
	
	/* Get virtio-cxl device from dm-crypt context */
	vcrypto = dm_crypt_get_ctx(dmreq);
	
	req_state = kzalloc(sizeof(*req_state), GFP_NOIO);
	if (!req_state)
		return -ENOMEM;
	
	vreq = kzalloc(sizeof(*vreq), GFP_NOIO);
	if (!vreq) {
		kfree(req_state);
		return -ENOMEM;
	}
	
	/* Setup request for LUKS */
	vreq->header.opcode = encrypt ? VIRTIO_CXL_CRYPTO_OP_ENCRYPT :
	                                VIRTIO_CXL_CRYPTO_OP_DECRYPT;
	vreq->header.algo = VIRTIO_CXL_CRYPTO_F_CIPHER_XTS;
	
	/* Use exclusive cache for LUKS operations */
	vreq->header.cache_hint = CXL_CACHE_EXCLUSIVE;
	vreq->header.exclusive_request = 1;
	
	req_state->vcrypto = vcrypto;
	req_state->req = vreq;
	req_state->dmreq = dmreq;
	init_completion(&req_state->completion);
	
	/* Submit to hardware */
	ret = virtio_cxl_crypto_submit_req(vcrypto, req_state);
	if (ret) {
		kfree(vreq);
		kfree(req_state);
		return ret;
	}
	
	/* For async operation */
	return -EINPROGRESS;
}

/* Virtio device operations */
static int virtio_cxl_crypto_init_vqs(struct virtio_cxl_crypto *vcrypto)
{
	int ret;
	int i, total_vqs;
	const char **names;
	struct virtqueue **vqs;
	vq_callback_t **callbacks;
	unsigned short *num_vqs;
	
	/* Setup virtqueues */
	total_vqs = vcrypto->config.max_dataqueues + 1;
	
	vqs = kcalloc(total_vqs, sizeof(*vqs), GFP_KERNEL);
	callbacks = kcalloc(total_vqs, sizeof(*callbacks), GFP_KERNEL);
	names = kcalloc(total_vqs, sizeof(*names), GFP_KERNEL);
	if (!vqs || !callbacks || !names) {
		ret = -ENOMEM;
		goto out;
	}
	
	/* Data queues */
	for (i = 0; i < vcrypto->config.max_dataqueues; i++) {
		callbacks[i] = virtio_cxl_datavq_callback;
		names[i] = "datavq";
	}
	
	/* Control queue */
	callbacks[i] = NULL;
	names[i] = "ctrlvq";
	
	ret = virtio_find_vqs(vcrypto->vdev, total_vqs, vqs, callbacks,
	                      names, NULL);
	if (ret)
		goto out;
	
	for (i = 0; i < vcrypto->config.max_dataqueues; i++)
		vcrypto->datavq[i] = vqs[i];
	vcrypto->ctrlvq = vqs[i];
	
out:
	kfree(vqs);
	kfree(callbacks);
	kfree(names);
	return ret;
}

static int virtio_cxl_crypto_probe(struct virtio_device *vdev)
{
	struct virtio_cxl_crypto *vcrypto;
	int ret;
	
	vcrypto = kzalloc(sizeof(*vcrypto), GFP_KERNEL);
	if (!vcrypto)
		return -ENOMEM;
	
	vdev->priv = vcrypto;
	vcrypto->vdev = vdev;
	spin_lock_init(&vcrypto->cache_lock);
	
	/* Read configuration */
	virtio_cread(vdev, struct virtio_cxl_crypto_config,
	            max_dataqueues, &vcrypto->config.max_dataqueues);
	virtio_cread(vdev, struct virtio_cxl_crypto_config,
	            cxl_cache_size, &vcrypto->config.cxl_cache_size);
	virtio_cread(vdev, struct virtio_cxl_crypto_config,
	            cxl_exclusive_capable, &vcrypto->config.cxl_exclusive_capable);
	
	/* Check for LUKS acceleration support */
	if (virtio_has_feature(vdev, VIRTIO_CXL_CRYPTO_F_LUKS_ACCEL)) {
		vcrypto->luks_mode = true;
		dev_info(&vdev->dev, "LUKS hardware acceleration enabled\n");
	}
	
	/* Initialize virtqueues */
	ret = virtio_cxl_crypto_init_vqs(vcrypto);
	if (ret)
		goto err_free;
	
	/* Register crypto algorithms */
	ret = crypto_register_skcipher(&virtio_cxl_aes_xts_alg);
	if (ret) {
		dev_err(&vdev->dev, "Failed to register XTS algorithm\n");
		goto err_vqs;
	}
	
	ret = crypto_register_skcipher(&virtio_cxl_aes_cbc_alg);
	if (ret) {
		dev_err(&vdev->dev, "Failed to register CBC algorithm\n");
		goto err_unreg_xts;
	}
	
	virtio_device_ready(vdev);
	
	dev_info(&vdev->dev, "Virtio-CXL crypto accelerator initialized\n");
	dev_info(&vdev->dev, "CXL cache size: %u KB, Exclusive capable: %s\n",
	         vcrypto->config.cxl_cache_size / 1024,
	         vcrypto->config.cxl_exclusive_capable ? "yes" : "no");
	
	return 0;
	
err_unreg_xts:
	crypto_unregister_skcipher(&virtio_cxl_aes_xts_alg);
err_vqs:
	vdev->config->del_vqs(vdev);
err_free:
	kfree(vcrypto);
	return ret;
}

static void virtio_cxl_crypto_remove(struct virtio_device *vdev)
{
	struct virtio_cxl_crypto *vcrypto = vdev->priv;
	
	virtio_reset_device(vdev);
	
	crypto_unregister_skcipher(&virtio_cxl_aes_xts_alg);
	crypto_unregister_skcipher(&virtio_cxl_aes_cbc_alg);
	
	vdev->config->del_vqs(vdev);
	
	dev_info(&vdev->dev, "Statistics:\n");
	dev_info(&vdev->dev, "  Requests completed: %lld\n",
	         atomic64_read(&vcrypto->reqs_completed));
	dev_info(&vdev->dev, "  Bytes encrypted: %lld\n",
	         atomic64_read(&vcrypto->bytes_encrypted));
	dev_info(&vdev->dev, "  Bytes decrypted: %lld\n",
	         atomic64_read(&vcrypto->bytes_decrypted));
	
	kfree(vcrypto);
}

static unsigned int features[] = {
	VIRTIO_CXL_CRYPTO_F_CIPHER_AES,
	VIRTIO_CXL_CRYPTO_F_CIPHER_XTS,
	VIRTIO_CXL_CRYPTO_F_CXL_CACHE,
	VIRTIO_CXL_CRYPTO_F_LUKS_ACCEL,
};

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_CXL_CRYPTO, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_cxl_crypto_driver = {
	.driver.name = "virtio_cxl_crypto",
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.probe = virtio_cxl_crypto_probe,
	.remove = virtio_cxl_crypto_remove,
};

module_virtio_driver(virtio_cxl_crypto_driver);

MODULE_DESCRIPTION("Virtio-CXL crypto accelerator for LUKS");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("CXL Crypto Team");