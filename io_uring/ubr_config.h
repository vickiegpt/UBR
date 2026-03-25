/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_UBR_CONFIG_H
#define IO_URING_UBR_CONFIG_H

/*
 * UBR Feature Flags — comment out to disable.
 * When disabled, the code compiles as if the feature doesn't exist.
 */

/* UMEM zero-copy path for unified_ops (Approach 3) */
#define UBR_UMEM_ZEROCOPY

/* Chain scheduler — currently disabled */
/* #define UBR_ENABLE_CHAIN_SCHED */

#endif /* IO_URING_UBR_CONFIG_H */
