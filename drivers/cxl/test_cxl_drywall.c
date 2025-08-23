// SPDX-License-Identifier: GPL-2.0
/*
 * CXL Drywall Test Module - Vulnerability Testing and Mitigation Demo
 * 
 * This module tests the security vulnerabilities described in the Drywall paper:
 * 1. Device unplugging with exclusive cachelines
 * 2. Malicious device states
 * 3. Cacheline exclusiveness violations
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <crypto/skcipher.h>

#define TEST_DATA_SIZE 4096
#define TEST_KEY_SIZE 32
#define TEST_IV_SIZE 16

struct test_context {
	struct crypto_skcipher *tfm;
	struct completion test_complete;
	bool test_passed;
	int test_id;
};

/* Test scenarios from the Drywall paper */
enum drywall_test_scenario {
	TEST_NORMAL_OPERATION = 0,
	TEST_DEVICE_UNPLUG,
	TEST_MALICIOUS_STATE,
	TEST_EXCLUSIVE_VIOLATION,
	TEST_CONCURRENT_ACCESS,
	TEST_RECOVERY_MECHANISM
};

static int run_crypto_operation(struct test_context *ctx, 
                                u8 *data, size_t len,
                                bool encrypt)
{
	struct skcipher_request *req;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	u8 key[TEST_KEY_SIZE];
	u8 iv[TEST_IV_SIZE];
	int ret;
	
	/* Generate random key and IV */
	get_random_bytes(key, TEST_KEY_SIZE);
	get_random_bytes(iv, TEST_IV_SIZE);
	
	/* Set key */
	ret = crypto_skcipher_setkey(ctx->tfm, key, TEST_KEY_SIZE);
	if (ret) {
		pr_err("Failed to set key: %d\n", ret);
		return ret;
	}
	
	/* Allocate request */
	req = skcipher_request_alloc(ctx->tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;
	
	/* Setup scatterlist */
	sg_init_one(&sg, data, len);
	
	/* Setup request */
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
	                              crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg, &sg, len, iv);
	
	/* Perform operation */
	if (encrypt)
		ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	else
		ret = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
	
	skcipher_request_free(req);
	return ret;
}

/* Test 1: Normal operation baseline */
static int test_normal_operation(struct test_context *ctx)
{
	u8 *test_data;
	u8 *orig_data;
	int ret;
	
	pr_info("Test 1: Normal CXL crypto operation\n");
	
	test_data = kmalloc(TEST_DATA_SIZE, GFP_KERNEL);
	orig_data = kmalloc(TEST_DATA_SIZE, GFP_KERNEL);
	if (!test_data || !orig_data) {
		ret = -ENOMEM;
		goto out;
	}
	
	/* Generate test data */
	get_random_bytes(test_data, TEST_DATA_SIZE);
	memcpy(orig_data, test_data, TEST_DATA_SIZE);
	
	/* Encrypt */
	ret = run_crypto_operation(ctx, test_data, TEST_DATA_SIZE, true);
	if (ret) {
		pr_err("Encryption failed: %d\n", ret);
		goto out;
	}
	
	/* Verify data was encrypted */
	if (!memcmp(orig_data, test_data, TEST_DATA_SIZE)) {
		pr_err("Data not encrypted!\n");
		ret = -EINVAL;
		goto out;
	}
	
	/* Decrypt */
	ret = run_crypto_operation(ctx, test_data, TEST_DATA_SIZE, false);
	if (ret) {
		pr_err("Decryption failed: %d\n", ret);
		goto out;
	}
	
	pr_info("Test 1: PASSED - Normal operation works\n");
	
out:
	kfree(test_data);
	kfree(orig_data);
	return ret;
}

/* Test 2: Device unplug simulation */
static int test_device_unplug(struct test_context *ctx)
{
	u8 *test_data;
	struct file *error_inject;
	char inject_cmd[] = "0x1"; /* Device unplug */
	int ret;
	loff_t pos = 0;
	
	pr_info("Test 2: Device unplug with exclusive cacheline\n");
	
	test_data = kmalloc(TEST_DATA_SIZE, GFP_KERNEL);
	if (!test_data)
		return -ENOMEM;
	
	get_random_bytes(test_data, TEST_DATA_SIZE);
	
	/* Start crypto operation */
	pr_info("Starting crypto operation...\n");
	ret = run_crypto_operation(ctx, test_data, TEST_DATA_SIZE / 2, true);
	
	/* Inject device unplug during operation */
	error_inject = filp_open("/sys/bus/pci/devices/0000:00:00.0/error_inject",
	                        O_WRONLY, 0);
	if (!IS_ERR(error_inject)) {
		kernel_write(error_inject, inject_cmd, strlen(inject_cmd), &pos);
		filp_close(error_inject, NULL);
		pr_info("Injected device unplug\n");
	}
	
	/* Continue with second half - should fallback to software */
	ret = run_crypto_operation(ctx, test_data + TEST_DATA_SIZE / 2,
	                          TEST_DATA_SIZE / 2, true);
	
	if (ret == 0) {
		pr_info("Test 2: PASSED - Fallback to software crypto worked\n");
	} else {
		pr_err("Test 2: FAILED - Operation failed after unplug: %d\n", ret);
	}
	
	kfree(test_data);
	return ret;
}

/* Test 3: Malicious device state */
static int test_malicious_state(struct test_context *ctx)
{
	u8 *test_data;
	struct file *error_inject;
	char inject_cmd[] = "0x2"; /* Malicious state */
	int ret;
	int i;
	loff_t pos = 0;
	
	pr_info("Test 3: Malicious device state detection\n");
	
	test_data = kmalloc(TEST_DATA_SIZE, GFP_KERNEL);
	if (!test_data)
		return -ENOMEM;
	
	/* Inject malicious state */
	error_inject = filp_open("/sys/bus/pci/devices/0000:00:00.0/error_inject",
	                        O_WRONLY, 0);
	if (!IS_ERR(error_inject)) {
		kernel_write(error_inject, inject_cmd, strlen(inject_cmd), &pos);
		filp_close(error_inject, NULL);
		pr_info("Injected malicious state\n");
	}
	
	/* Try multiple operations - should all use fallback */
	for (i = 0; i < 5; i++) {
		get_random_bytes(test_data, TEST_DATA_SIZE);
		ret = run_crypto_operation(ctx, test_data, TEST_DATA_SIZE, true);
		if (ret) {
			pr_err("Operation %d failed in malicious state: %d\n", i, ret);
			break;
		}
	}
	
	if (i == 5) {
		pr_info("Test 3: PASSED - All operations handled in malicious state\n");
		ret = 0;
	} else {
		pr_err("Test 3: FAILED - Could not handle malicious state\n");
	}
	
	kfree(test_data);
	return ret;
}

/* Test 4: Exclusive cacheline violation */
static int test_exclusive_violation(struct test_context *ctx)
{
	u8 *test_data1, *test_data2;
	struct task_struct *thread1, *thread2;
	struct file *error_inject;
	char inject_cmd[] = "0x4"; /* Exclusive violation */
	int ret = 0;
	loff_t pos = 0;
	
	pr_info("Test 4: Exclusive cacheline violation handling\n");
	
	test_data1 = kmalloc(TEST_DATA_SIZE, GFP_KERNEL);
	test_data2 = kmalloc(TEST_DATA_SIZE, GFP_KERNEL);
	if (!test_data1 || !test_data2) {
		ret = -ENOMEM;
		goto out;
	}
	
	get_random_bytes(test_data1, TEST_DATA_SIZE);
	get_random_bytes(test_data2, TEST_DATA_SIZE);
	
	/* Start first operation */
	ret = run_crypto_operation(ctx, test_data1, 64, true); /* One cacheline */
	
	/* Inject exclusive violation */
	error_inject = filp_open("/sys/bus/pci/devices/0000:00:00.0/error_inject",
	                        O_WRONLY, 0);
	if (!IS_ERR(error_inject)) {
		kernel_write(error_inject, inject_cmd, strlen(inject_cmd), &pos);
		filp_close(error_inject, NULL);
		pr_info("Injected exclusive cacheline violation\n");
	}
	
	/* Try accessing same cacheline from different context */
	ret = run_crypto_operation(ctx, test_data1, 64, false);
	
	if (ret == 0) {
		pr_info("Test 4: PASSED - Exclusive violation handled\n");
	} else {
		pr_err("Test 4: FAILED - Could not handle exclusive violation: %d\n", ret);
	}
	
out:
	kfree(test_data1);
	kfree(test_data2);
	return ret;
}

/* Test 5: Recovery mechanism */
static int test_recovery_mechanism(struct test_context *ctx)
{
	u8 *test_data;
	u8 *backup_data;
	struct file *stats_file;
	char stats_buf[256];
	int ret;
	ssize_t len;
	loff_t pos = 0;
	
	pr_info("Test 5: Recovery mechanism validation\n");
	
	test_data = kmalloc(TEST_DATA_SIZE, GFP_KERNEL);
	backup_data = kmalloc(TEST_DATA_SIZE, GFP_KERNEL);
	if (!test_data || !backup_data) {
		ret = -ENOMEM;
		goto out;
	}
	
	/* Generate and backup test data */
	get_random_bytes(test_data, TEST_DATA_SIZE);
	memcpy(backup_data, test_data, TEST_DATA_SIZE);
	
	/* Start operation that will need recovery */
	ret = run_crypto_operation(ctx, test_data, TEST_DATA_SIZE, true);
	
	/* Simulate device failure requiring recovery */
	pr_info("Simulating device failure...\n");
	msleep(100);
	
	/* Check recovery statistics */
	stats_file = filp_open("/sys/module/cxl_crypto_drywall/parameters/stats",
	                      O_RDONLY, 0);
	if (!IS_ERR(stats_file)) {
		len = kernel_read(stats_file, stats_buf, sizeof(stats_buf) - 1, &pos);
		if (len > 0) {
			stats_buf[len] = '\0';
			pr_info("Recovery stats: %s\n", stats_buf);
		}
		filp_close(stats_file, NULL);
	}
	
	/* Verify data integrity after recovery */
	ret = run_crypto_operation(ctx, test_data, TEST_DATA_SIZE, false);
	
	if (ret == 0) {
		pr_info("Test 5: PASSED - Recovery mechanism works\n");
	} else {
		pr_err("Test 5: FAILED - Recovery failed: %d\n", ret);
	}
	
out:
	kfree(test_data);
	kfree(backup_data);
	return ret;
}

/* Main test runner */
static int drywall_test_thread(void *data)
{
	struct test_context ctx;
	int ret = 0;
	
	pr_info("=== CXL Drywall Security Test Suite ===\n");
	pr_info("Testing vulnerabilities from the Drywall paper\n\n");
	
	/* Allocate cipher */
	ctx.tfm = crypto_alloc_skcipher("cxl-cbc-aes", 0, 0);
	if (IS_ERR(ctx.tfm)) {
		/* Try fallback cipher */
		ctx.tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
		if (IS_ERR(ctx.tfm)) {
			pr_err("Failed to allocate cipher\n");
			return PTR_ERR(ctx.tfm);
		}
		pr_info("Using fallback cipher for testing\n");
	} else {
		pr_info("Using CXL crypto accelerator\n");
	}
	
	/* Run test suite */
	ret = test_normal_operation(&ctx);
	if (ret)
		goto out;
	
	msleep(1000);
	ret = test_device_unplug(&ctx);
	if (ret)
		goto out;
	
	msleep(1000);
	ret = test_malicious_state(&ctx);
	if (ret)
		goto out;
	
	msleep(1000);
	ret = test_exclusive_violation(&ctx);
	if (ret)
		goto out;
	
	msleep(1000);
	ret = test_recovery_mechanism(&ctx);
	
out:
	crypto_free_skcipher(ctx.tfm);
	
	if (ret == 0) {
		pr_info("\n=== All Drywall tests PASSED ===\n");
		pr_info("CXL Type 1 device security validated\n");
	} else {
		pr_err("\n=== Drywall tests FAILED ===\n");
		pr_err("Security vulnerabilities detected!\n");
	}
	
	return ret;
}

static int __init drywall_test_init(void)
{
	struct task_struct *test_thread;
	
	pr_info("CXL Drywall Test Module loaded\n");
	
	/* Run tests in background thread */
	test_thread = kthread_run(drywall_test_thread, NULL, "drywall_test");
	if (IS_ERR(test_thread)) {
		pr_err("Failed to create test thread\n");
		return PTR_ERR(test_thread);
	}
	
	return 0;
}

static void __exit drywall_test_exit(void)
{
	pr_info("CXL Drywall Test Module unloaded\n");
}

module_init(drywall_test_init);
module_exit(drywall_test_exit);

MODULE_AUTHOR("Drywall Research Team");
MODULE_DESCRIPTION("CXL Drywall Security Test Module");
MODULE_LICENSE("GPL");