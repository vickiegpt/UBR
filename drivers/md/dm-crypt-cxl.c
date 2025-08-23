// SPDX-License-Identifier: GPL-2.0
/*
 * dm-crypt CXL Hardware Acceleration Module
 * 
 * This module enables dm-crypt/LUKS to use CXL Type 1 crypto accelerators
 * through virtio transport for high-performance disk encryption
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device-mapper.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#define DM_MSG_PREFIX "crypt-cxl"

/* CXL acceleration modes */
enum cxl_accel_mode {
	CXL_ACCEL_NONE = 0,
	CXL_ACCEL_CACHE_ONLY,    /* Use CXL cache but software crypto */
	CXL_ACCEL_CRYPTO_ONLY,    /* Use CXL crypto but not cache */
	CXL_ACCEL_FULL,          /* Use both CXL cache and crypto */
};

struct dm_crypt_cxl_ctx {
	struct dm_target *ti;
	struct crypto_skcipher *tfm;
	
	/* CXL specific */
	enum cxl_accel_mode accel_mode;
	bool use_exclusive_cache;
	
	/* Performance counters */
	atomic64_t sectors_encrypted;
	atomic64_t sectors_decrypted;
	atomic64_t cache_hits;
	atomic64_t hw_accel_count;
	
	/* Workqueue for async operations */
	struct workqueue_struct *crypt_wq;
	
	/* Key management */
	u8 *key;
	unsigned int key_size;
	
	/* Device info */
	struct dm_dev *dev;
	sector_t start;
	
	/* IV generation */
	u64 iv_offset;
	unsigned int iv_size;
	
	/* Cipher configuration */
	char *cipher_string;
	char *cipher_mode;
};

struct dm_crypt_cxl_io {
	struct dm_crypt_cxl_ctx *ctx;
	struct bio *base_bio;
	struct work_struct work;
	
	atomic_t io_pending;
	blk_status_t error;
	
	sector_t sector;
	
	struct skcipher_request *req;
};

/* Check if CXL hardware acceleration is available */
static bool dm_crypt_cxl_available(void)
{
	struct crypto_skcipher *tfm;
	bool available = false;
	
	/* Try to allocate CXL-accelerated cipher */
	tfm = crypto_alloc_skcipher("virtio-cxl-xts-aes", 0, 0);
	if (!IS_ERR(tfm)) {
		available = true;
		crypto_free_skcipher(tfm);
		DMINFO("CXL hardware acceleration available");
	} else {
		tfm = crypto_alloc_skcipher("cxl-xts-aes", 0, 0);
		if (!IS_ERR(tfm)) {
			available = true;
			crypto_free_skcipher(tfm);
			DMINFO("CXL hardware acceleration available (native)");
		}
	}
	
	return available;
}

/* Select best cipher based on hardware availability */
static const char *dm_crypt_cxl_select_cipher(const char *cipher_string)
{
	if (strstr(cipher_string, "xts(aes)") || strstr(cipher_string, "aes-xts")) {
		if (dm_crypt_cxl_available()) {
			DMINFO("Using CXL-accelerated XTS-AES");
			return "virtio-cxl-xts-aes";
		}
	}
	
	if (strstr(cipher_string, "cbc(aes)") || strstr(cipher_string, "aes-cbc")) {
		if (dm_crypt_cxl_available()) {
			DMINFO("Using CXL-accelerated CBC-AES");
			return "virtio-cxl-cbc-aes";
		}
	}
	
	/* Fallback to software implementation */
	return cipher_string;
}

/* Generate IV for sector */
static void dm_crypt_cxl_gen_iv(struct dm_crypt_cxl_ctx *ctx, u8 *iv,
                                struct dm_crypt_cxl_io *io)
{
	__le64 val;
	
	memset(iv, 0, ctx->iv_size);
	val = cpu_to_le64(io->sector + ctx->iv_offset);
	memcpy(iv, &val, sizeof(val));
}

/* Process crypto request */
static void dm_crypt_cxl_process_request(struct dm_crypt_cxl_io *io, bool encrypt)
{
	struct dm_crypt_cxl_ctx *ctx = io->ctx;
	struct bio_vec bvec;
	struct bvec_iter iter;
	struct scatterlist sg;
	u8 iv[32];
	int ret;
	
	/* Generate IV */
	dm_crypt_cxl_gen_iv(ctx, iv, io);
	
	/* Allocate crypto request */
	io->req = skcipher_request_alloc(ctx->tfm, GFP_NOIO);
	if (!io->req) {
		io->error = BLK_STS_RESOURCE;
		return;
	}
	
	skcipher_request_set_callback(io->req, CRYPTO_TFM_REQ_MAY_SLEEP,
	                              NULL, NULL);
	
	/* Process each bio segment */
	bio_for_each_segment(bvec, io->base_bio, iter) {
		sg_init_one(&sg, page_address(bvec.bv_page) + bvec.bv_offset,
		            bvec.bv_len);
		
		skcipher_request_set_crypt(io->req, &sg, &sg, bvec.bv_len, iv);
		
		if (encrypt) {
			ret = crypto_skcipher_encrypt(io->req);
			atomic64_add(bvec.bv_len >> 9, &ctx->sectors_encrypted);
		} else {
			ret = crypto_skcipher_decrypt(io->req);
			atomic64_add(bvec.bv_len >> 9, &ctx->sectors_decrypted);
		}
		
		if (ret) {
			io->error = BLK_STS_IOERR;
			break;
		}
		
		/* Update IV for next sector */
		crypto_inc(iv, ctx->iv_size);
		
		/* Track hardware acceleration usage */
		if (ctx->accel_mode >= CXL_ACCEL_CRYPTO_ONLY)
			atomic64_inc(&ctx->hw_accel_count);
	}
	
	skcipher_request_free(io->req);
}

/* Work function for async crypto */
static void dm_crypt_cxl_work(struct work_struct *work)
{
	struct dm_crypt_cxl_io *io = container_of(work, struct dm_crypt_cxl_io, work);
	struct bio *bio = io->base_bio;
	bool encrypt = bio_data_dir(bio) == WRITE;
	
	dm_crypt_cxl_process_request(io, encrypt);
	
	bio->bi_status = io->error;
	bio_endio(bio);
	
	mempool_free(io, io->ctx->ti->private);
}

/* Map function for dm-crypt */
static int dm_crypt_cxl_map(struct dm_target *ti, struct bio *bio)
{
	struct dm_crypt_cxl_ctx *ctx = ti->private;
	struct dm_crypt_cxl_io *io;
	
	/* Allocate IO context */
	io = mempool_alloc(ti->private, GFP_NOIO);
	if (!io)
		return DM_MAPIO_REQUEUE;
	
	io->ctx = ctx;
	io->base_bio = bio;
	io->sector = bio->bi_iter.bi_sector;
	io->error = 0;
	atomic_set(&io->io_pending, 1);
	
	/* Remap to underlying device */
	bio_set_dev(bio, ctx->dev->bdev);
	bio->bi_iter.bi_sector = ctx->start + io->sector;
	
	/* For reads, submit immediately and decrypt on completion */
	if (bio_data_dir(bio) == READ) {
		generic_make_request(bio);
		INIT_WORK(&io->work, dm_crypt_cxl_work);
		queue_work(ctx->crypt_wq, &io->work);
	} else {
		/* For writes, encrypt first then submit */
		INIT_WORK(&io->work, dm_crypt_cxl_work);
		queue_work(ctx->crypt_wq, &io->work);
	}
	
	return DM_MAPIO_SUBMITTED;
}

/* Constructor for dm-crypt-cxl target */
static int dm_crypt_cxl_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct dm_crypt_cxl_ctx *ctx;
	const char *cipher_api;
	char dummy;
	int ret;
	
	if (argc < 5) {
		ti->error = "Not enough arguments";
		return -EINVAL;
	}
	
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		ti->error = "Cannot allocate context";
		return -ENOMEM;
	}
	
	ti->private = ctx;
	ctx->ti = ti;
	
	/* Parse cipher string */
	ctx->cipher_string = kstrdup(argv[0], GFP_KERNEL);
	if (!ctx->cipher_string) {
		ret = -ENOMEM;
		goto err;
	}
	
	/* Select best cipher implementation */
	cipher_api = dm_crypt_cxl_select_cipher(ctx->cipher_string);
	
	/* Allocate cipher */
	ctx->tfm = crypto_alloc_skcipher(cipher_api, 0, 0);
	if (IS_ERR(ctx->tfm)) {
		ti->error = "Error allocating crypto tfm";
		ret = PTR_ERR(ctx->tfm);
		goto err;
	}
	
	/* Parse and set key */
	ctx->key_size = strlen(argv[1]) >> 1;
	ctx->key = kzalloc(ctx->key_size, GFP_KERNEL);
	if (!ctx->key) {
		ret = -ENOMEM;
		goto err;
	}
	
	if (hex2bin(ctx->key, argv[1], ctx->key_size) < 0) {
		ti->error = "Invalid key";
		ret = -EINVAL;
		goto err;
	}
	
	ret = crypto_skcipher_setkey(ctx->tfm, ctx->key, ctx->key_size);
	if (ret) {
		ti->error = "Error setting key";
		goto err;
	}
	
	/* Parse IV offset */
	if (sscanf(argv[2], "%llu%c", &ctx->iv_offset, &dummy) != 1) {
		ti->error = "Invalid IV offset";
		ret = -EINVAL;
		goto err;
	}
	
	/* Get device */
	ret = dm_get_device(ti, argv[3], dm_table_get_mode(ti->table), &ctx->dev);
	if (ret) {
		ti->error = "Device lookup failed";
		goto err;
	}
	
	/* Parse start sector */
	if (sscanf(argv[4], "%llu%c", &ctx->start, &dummy) != 1) {
		ti->error = "Invalid start sector";
		ret = -EINVAL;
		goto err;
	}
	
	/* Setup IV size */
	ctx->iv_size = crypto_skcipher_ivsize(ctx->tfm);
	
	/* Check for CXL acceleration */
	if (strstr(cipher_api, "cxl")) {
		ctx->accel_mode = CXL_ACCEL_FULL;
		DMINFO("CXL full acceleration enabled");
	} else {
		ctx->accel_mode = CXL_ACCEL_NONE;
	}
	
	/* Create workqueue */
	ctx->crypt_wq = alloc_workqueue("dm-crypt-cxl", WQ_MEM_RECLAIM | WQ_CPU_INTENSIVE, 1);
	if (!ctx->crypt_wq) {
		ti->error = "Cannot allocate workqueue";
		ret = -ENOMEM;
		goto err;
	}
	
	/* Initialize statistics */
	atomic64_set(&ctx->sectors_encrypted, 0);
	atomic64_set(&ctx->sectors_decrypted, 0);
	atomic64_set(&ctx->cache_hits, 0);
	atomic64_set(&ctx->hw_accel_count, 0);
	
	ti->num_flush_bios = 1;
	
	return 0;
	
err:
	if (ctx->crypt_wq)
		destroy_workqueue(ctx->crypt_wq);
	if (ctx->dev)
		dm_put_device(ti, ctx->dev);
	kfree(ctx->key);
	if (!IS_ERR_OR_NULL(ctx->tfm))
		crypto_free_skcipher(ctx->tfm);
	kfree(ctx->cipher_string);
	kfree(ctx);
	return ret;
}

/* Destructor */
static void dm_crypt_cxl_dtr(struct dm_target *ti)
{
	struct dm_crypt_cxl_ctx *ctx = ti->private;
	
	ti->private = NULL;
	
	if (ctx->crypt_wq)
		destroy_workqueue(ctx->crypt_wq);
	
	/* Print statistics */
	DMINFO("CXL Crypto Statistics:");
	DMINFO("  Sectors encrypted: %lld", atomic64_read(&ctx->sectors_encrypted));
	DMINFO("  Sectors decrypted: %lld", atomic64_read(&ctx->sectors_decrypted));
	DMINFO("  Hardware accelerations: %lld", atomic64_read(&ctx->hw_accel_count));
	
	dm_put_device(ti, ctx->dev);
	kfree(ctx->key);
	crypto_free_skcipher(ctx->tfm);
	kfree(ctx->cipher_string);
	kfree(ctx);
}

/* Status function */
static void dm_crypt_cxl_status(struct dm_target *ti, status_type_t type,
                                unsigned status_flags, char *result, unsigned maxlen)
{
	struct dm_crypt_cxl_ctx *ctx = ti->private;
	unsigned sz = 0;
	
	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%lld %lld",
		       atomic64_read(&ctx->sectors_encrypted),
		       atomic64_read(&ctx->sectors_decrypted));
		if (ctx->accel_mode >= CXL_ACCEL_CRYPTO_ONLY)
			DMEMIT(" cxl_accel:%lld", atomic64_read(&ctx->hw_accel_count));
		break;
		
	case STATUSTYPE_TABLE:
		DMEMIT("%s ", ctx->cipher_string);
		DMEMIT("%llu %s %llu",
		       (unsigned long long)ctx->iv_offset,
		       ctx->dev->name,
		       (unsigned long long)ctx->start);
		break;
		
	case STATUSTYPE_IMA:
		break;
	}
}

/* Target registration */
static struct target_type dm_crypt_cxl_target = {
	.name = "crypt-cxl",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = dm_crypt_cxl_ctr,
	.dtr = dm_crypt_cxl_dtr,
	.map = dm_crypt_cxl_map,
	.status = dm_crypt_cxl_status,
};

static int __init dm_crypt_cxl_init(void)
{
	int ret;
	
	ret = dm_register_target(&dm_crypt_cxl_target);
	if (ret < 0) {
		DMERR("Failed to register target: %d", ret);
		return ret;
	}
	
	DMINFO("CXL-accelerated dm-crypt target registered");
	
	if (dm_crypt_cxl_available())
		DMINFO("CXL hardware acceleration detected and enabled");
	else
		DMINFO("No CXL acceleration available, using software crypto");
	
	return 0;
}

static void __exit dm_crypt_cxl_exit(void)
{
	dm_unregister_target(&dm_crypt_cxl_target);
	DMINFO("CXL-accelerated dm-crypt target unregistered");
}

module_init(dm_crypt_cxl_init);
module_exit(dm_crypt_cxl_exit);

MODULE_DESCRIPTION("CXL hardware accelerated dm-crypt target");
MODULE_AUTHOR("CXL Crypto Team");
MODULE_LICENSE("GPL");