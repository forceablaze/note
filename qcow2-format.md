title: "qcow2 format"
date: 2015-09-24 17:37:05
tags: Linux,qemu
---

### QCOW2

QEMU copy-on-write version 2

##### Wide range of features
+ Read only backing files
+ Snapshot (internal external)
	+ supports multiple virtual machine snapshots through a new, flexible model for storing snapshots.
+ Zero clusters partial allocation 
+ Compression
	+ zlib
+ Encryption
	+ 128-bit AES-CBC

##### Create QCOW2 image
```bash
$ qemu-img create -f qcow2 rico.qcow2 5G
$ qemu-info rico.qcow2
image: rico.qcow2
file format: qcow2
virtual size: 5.0G (5368709120 bytes)
disk size: 196K
cluster_size: 65536
Format specific information:
    compat: 1.1
    lazy refcounts: false
    refcount bits: 16
    corrupt: false
```
##### supported options
+ compat
+ backing_file
+ backing_fmt
+ encryption
+ cluster_size
+ preallocation
+ lazy_refcounts
+ nocow


#### backing file
``` bash
$ qemu-img create -b rico.qcow2 -f qcow2 rico-1.qcow2
$ qemu-img info
image: rico-1.qcow2
file format: qcow2
virtual size: 5.0G (5368709120 bytes)
disk size: 196K
cluster_size: 65536
backing file: rico.qcow2
Format specific information:
    compat: 1.1
    lazy refcounts: false
    refcount bits: 16
    corrupt: false

# create backing based on rico-1.qcow2
$ qemu-img create -b rico-1.qcow2 -f qcow2 rico-1A.qcow2
$ qemu-img info --backing-chain rico-1A.qcow2
image: rico-1A.qcow2
file format: qcow2
virtual size: 5.0G (5368709120 bytes)
disk size: 196K
cluster_size: 65536
backing file: rico-1.qcow2
Format specific information:
    compat: 1.1
    lazy refcounts: false
    refcount bits: 16
    corrupt: false

image: rico-1.qcow2
file format: qcow2
virtual size: 5.0G (5368709120 bytes)
disk size: 196K
cluster_size: 65536
backing file: rico.qcow2
Format specific information:
    compat: 1.1
    lazy refcounts: false
    refcount bits: 16
    corrupt: false

image: rico.qcow2
file format: qcow2
virtual size: 5.0G (5368709120 bytes)
disk size: 196K
cluster_size: 65536
Format specific information:
    compat: 1.1
    lazy refcounts: false
    refcount bits: 16
    corrupt: false
```
Backing files are always opened **read-only**.

#### example:
base <- sn1 <- sn2 <- sn3 

現在要刪掉 sn2
有兩個方法 
1. 把 sn2 merge 到 sn1
``` bash
	qemu-img commit sn2.qcow2
	qemu-img rebase -u -b sn1.qcow2 sn3.qcow2
```
2. 把 sn2 merge 到 sn3 
``` bash
	qemu-img commit sn2.qcow2
	qemu-img rebase -u -b sn1.qcow2 sn3.qcow2
```
#### Shapshots

+ internal
	+ A type of snapshot, where a single QCOW2 file will hold both the ‘saved state’ and the ‘delta’ since that saved point. ‘Internal snapshots’ are very handy because it’s only a single file where all the snapshot info. is captured, and easy to copy/move around the machines.
+ external (backing file)
	+ Here, the ‘original qcow2 file’ will be in a ‘read-only’ saved state, and the new qcow2 file(which will be generated once snapshot is created) will be the delta for the changes. So, all the changes will now be written to this delta file. ‘External Snapshots’ are useful for **performing backups**. Also, external snapshot creates a qcow2 file with the original file as its backing image, and the backing file can be /read/ in parallel with the running qemu.

``` bash
$ qemu-img snapshot -c snap1 rico-1A.qcow2
$ qemu-img snapshot -c snap2 rico-1A.qcow2
$ qemu-img snapshot -l rico-1A.qcow2 
Snapshot list:
ID        TAG                 VM SIZE                DATE       VM CLOCK
1         snap1                     0 2015-09-25 09:58:36   00:00:00.000
2         snap2                     0 2015-09-25 09:59:36   00:00:00.000
```

https://kashyapc.fedorapeople.org/virt/lc-2012/snapshots-handout.html
http://wiki.qemu.org/Features/Snapshots
http://wiki.qemu.org/Features/Snapshots2


### General
A qcow2 image file is organized in units of constant size, which are called (host) clusters. A cluster is the unit in which all allocations are done, both for actual guest data and for image metadata.

Likewise, the virtual disk as seen by the guest is divided into (guest) clusters of the same size.

All numbers in qcow2 are stored in Big Endian byte order.

### Header

the default value of qcow2
``` c
#define QCOW_MAGIC (('Q' << 24) | ('F' << 16) | ('I' << 8) | 0xfb)

#define QCOW_CRYPT_NONE 0
#define QCOW_CRYPT_AES  1

#define QCOW_MAX_CRYPT_CLUSTERS 32
#define QCOW_MAX_SNAPSHOTS 65536

/* 8 MB refcount table is enough for 2 PB images at 64k cluster size
 * (128 GB for 512 byte clusters, 2 EB for 2 MB clusters) */
#define QCOW_MAX_REFTABLE_SIZE 0x800000

/* 32 MB L1 table is enough for 2 PB images at 64k cluster size
 * (128 GB for 512 byte clusters, 2 EB for 2 MB clusters) */
#define QCOW_MAX_L1_SIZE 0x2000000

/* Allow for an average of 1k per snapshot table entry, should be plenty of
 * space for snapshot names and IDs */
#define QCOW_MAX_SNAPSHOTS_SIZE (1024 * QCOW_MAX_SNAPSHOTS)

/* indicate that the refcount of the referenced cluster is exactly one. */
#define QCOW_OFLAG_COPIED     (1ULL << 63)
/* indicate that the cluster is compressed (they never have the copied flag) */
#define QCOW_OFLAG_COMPRESSED (1ULL << 62)
/* The cluster reads as all zeros */
#define QCOW_OFLAG_ZERO (1ULL << 0)

#define MIN_CLUSTER_BITS 9
#define MAX_CLUSTER_BITS 21

/* Must be at least 2 to cover COW */
#define MIN_L2_CACHE_SIZE 2 /* clusters */

/* Must be at least 4 to cover all cases of refcount table growth */
#define MIN_REFCOUNT_CACHE_SIZE 4 /* clusters */

/* Whichever is more */
#define DEFAULT_L2_CACHE_CLUSTERS 8 /* clusters */
#define DEFAULT_L2_CACHE_BYTE_SIZE 1048576 /* bytes */

/* The refblock cache needs only a fourth of the L2 cache size to cover as many
 * clusters */
#define DEFAULT_L2_REFCOUNT_SIZE_RATIO 4

#define DEFAULT_CLUSTER_SIZE 65536

```
``` c
typedef struct QCowHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t backing_file_offset;
    uint32_t backing_file_size;

    /* cluster size = 1 << cluster_bits
     * 9 <= cluster_bits <= 21
     * 512B <= cluster size <= 2M 
     */
    uint32_t cluster_bits;
    
    /* virtual disk size in bytes ex 100M = 0x0000000006400000 */
    uint64_t size; /* in bytes */
    
    uint32_t crypt_method;

    /* Number of entries in the active L1 table (8 bytes) */
    uint32_t l1_size; /* XXX: save number of clusters instead ? */

    /* Offset into the image file at which the active L1 table starts. Must be aligned to a cluster boundary. ex 0x0000000000030000 */
    uint64_t l1_table_offset;
    
    /* Offset into the image file at which the refcount table starts. Must be aligned to a cluster boundary. ex 0x0000000000010000 */
    uint64_t refcount_table_offset;

    /* Number of clusters that the refcount table occupies. initialized value = 1
     * describes the size of the refcount table.
     */
    uint32_t refcount_table_clusters;
    
    /* Max number of snapshots is 64K */
    uint32_t nb_snapshots;
    
    /* Offset into the image file at which the snapshot table starts. Must be aligned to a cluster boundary. zero if has no snapshot. */
    uint64_t snapshots_offset;

    /* The following fields are only valid for version >= 3
     * Bit 0: Dirty bit. If this bit is set then refcounts may be inconsistent, make sure to scan L1/L2 tables to repair refcounts before accessing the image.
     * Bit 1: Corrupt bit. If this bit is set then any data structure may be corrupt and the image must not be written to (unless for regaining consistency).
     */
    uint64_t incompatible_features;

    /* Lazy refcounts bit. If this bit is set then lazy refcount updates can be used. This means marking the image file dirty and postponing refcount metadata updates. */
    uint64_t compatible_features;
    uint64_t autoclear_features;

    /* Describes the width of a reference count block entry (width in bits: refcount_bits = 1 << refcount_order). For version 2 images, the order is always assumed to be 4 (i.e. refcount_bits = 16). This value may not exceed 6 (i.e. refcount_bits = 64).
     * refcount_order = 4 => refcount block entry size = 2 bytes
     */
    uint32_t refcount_order;

    /* Length of the header structure in bytes. For version 2 images, the length is always assumed to be 72 bytes. version 3 is 104 bytes */
    uint32_t header_length;
} QEMU_PACKED QCowHeader;

```

### Header Extension

**Directly after the image header**, optional sections called header extensions can be stored. Each extension has a structure like the following:
Byte

+ 0-3: Header extension type:
	+ 0x00000000  - End of the header extension area
	+ 0xE2792ACA - Backing file format name
	+ 0x6803F857 - Feature name table
	+ other            - Unknown header extension, can be safely ignored
+ 4-7: Length of the header extension data.
+ 8-n: Header extension data.
+ n-m: Padding to round up the header extension size to the next multiple of 8.


defined in block/qcow2.c
``` c
typedef struct {
    uint32_t magic;
    uint32_t len;
} QEMU_PACKED QCowExtension;

#define  QCOW2_EXT_MAGIC_END 0
#define  QCOW2_EXT_MAGIC_BACKING_FORMAT 0xE2792ACA
#define  QCOW2_EXT_MAGIC_FEATURE_TABLE 0x6803f857
```
#### Backing file

0xE2792ACA,00000005,71636F77,32000000

the header extension data is 0x71636F7732 = 'q', ' c', 'o', 'w', '2'.

If the image has a backing file then the backing file name should be stored in the remaining space **between the end of the headers extension area and the end of the first cluster**. It is not allowed to store other data here, so that an implementation can safely modify the header and add extensions without harming data of compatible features that is doesn't support. Compatible features that need space for additional data can use a header extension.

#### Feature name table

The feature name table is an optional header extension that contains the name for features used by the image. It can be used by applications that don't know the respective feature (e.g. because the feature was introduced only later) to display a useful error message.

defined in block/qcow2.h
``` c
typedef struct Qcow2Feature {
    /* Type of feature (select feature bitmap)
     *    0: Incompatible feature
     *    1: Compatible feature
     *    2: Autoclear feature
     */
    uint8_t type;
    
    /* Bit number within the selected feature bitmap (valid values: 0-63) */
    uint8_t bit;
    
    /* Feature name (padded with zeros, but not necessarily null terminated if it has full length) */
    char    name[46];
} QEMU_PACKED Qcow2Feature;
```
**the size of feature is 0x30 bytes**.

0x6803F857,00000090, 00006469....(multiple feature table)

the feature that length 144 bytes = 48 / 3 = 3 feature

+ dirty bit feature
0x00,00, 0x646972747920626974 ("dirty bit") 000000...
+ corrupt bit feature
0x00,01 0x636F727275707420626974 ("corrupt bit") 000000...
+ lazy refcounts feature
0x01,00 0x6C617A7920726566636F756E7473 ("lazy refcounts") 000000.... 

#### End of the header extension area
+ end of the header type, data length is zero.
0x00000000,00000000


### Host Cluster Management

qcow2 manages the allocation of host clusters by maintaining a refernce count for each host cluster. **A refcount of 0 means that the cluster is free, 1 means that it is used, and >= 2 means that it is used and any write access must perform a COW** (copy on write) operation.

The refcounts are managed in a **two-level table**. The first level is called **refcount table** and has a variable size (which is stored in the header). The refcount table can cover multiple clusters, however it needs to be contiguous in the image file.

**It contains pointers to the second level structures which are called refcount blocks** and are exactly **one clusters in size**.

Given a offset into the image file, the refcount of its cluster can be obtained as follows:

> refcount_block_entries = (cluster_size * 8 / refcount_bits)
> 
> refcount_block_index = (offset / cluster_size) % refcount_block_entires
> refcount_table_index = (offset / cluster_size) / refcount_block_entires
> 
> refcount_block = load_cluster(refcount_table[refcount_table_index])
> return refcount_block[refcount_block_index];

cluster_size = 64K
refcount_order = 4 -> refcount_bits = 16
=> the size of a refcount block is 64K * 8 / 16 = 0x8000 = 32K


>     Given image offset 0x20000
>     refcount_block_entries = 32KB
>     refcount_block_index = 0x20000 / 64K % 32K = 0
>     refcount_table_index = 0x20000 / 64K / 32K = 0


>     Given image offset 0x7FE00
>     refcount_block_entries = 32KB
>     refcount_block_index = 0x7FE00 / 64K % 32K = 7
>     refcount_table_index = 0x7FE00 / 64K / 32K = 0

a refcount table can handle 64K * 32KB data

**L2 table size = cluster_size / 8**
```c
    s->l2_bits = s->cluster_bits - 3; /* L2 is always one cluster */
    s->l2_size = 1 << s->l2_bits;
    /* 2^(s->refcount_order - 3) is the refcount width in bytes */
    s->refcount_block_bits = s->cluster_bits - (s->refcount_order - 3);
    s->refcount_block_size = 1 << s->refcount_block_bits;
    bs->total_sectors = header.size / 512;
    s->csize_shift = (62 - (s->cluster_bits - 8));
    s->csize_mask = (1 << (s->cluster_bits - 8)) - 1;
    s->cluster_offset_mask = (1LL << s->csize_shift) - 1;

    s->refcount_table_offset = header.refcount_table_offset;
    s->refcount_table_size =
        header.refcount_table_clusters << (s->cluster_bits - 3);
``` 

> if **refcount_order = 4, cluster_bits = 16, refcount_table_clusters = 1**
> refcount_block_bits = 16 - (4 - 3) = 15
> refcount_block_size = 1 << 15 = 32KB
> refcount_table_size = 1 << 13 = 8KB
> 8KB / 8B = 1K refcount table entry

#### Refcount table entry (8 bytes)
BIt

 - 0-8
Reserved (set to 0)
 - 9-63
 Bits 9-63 of **the offset into the image file at which the refcount block starts.** Must be aligned to a cluster boundary.
 If this is 0, the corresponding refcount block has not yet been allocated. All refcounts managed by this refcount block are 0.

ex:

> refcount table at offset 0x10000
> 0x0000, 000000020000 => offset 0x20000

#### Refcount block entry ( width = refcount_bit )
Bit

 - 0-x (x = refcount_bits - 1)
**Reference count of the cluster**. If refcount_bits implies a sub-type width, note that bit 0 means the least significant bit in this context.

ex:

> refcount_order = 4 => refcount_bit = 16, block entry size is 2 bytes
> 0x0001, 0001, 0001, 0001


### Cluster mapping
Just as for refcounts, qcow2 use **a two-level structure for the mapping of guest clusters to host clusters**. They are called L1 and L2 table.
The L1 table has a variable size (stored in the header) and may use multiple clusters, however it must be contiguous in the image file. L2 tables are exactly one cluster in size.

Given a offset into the virtual disk, the offset into the image file can be obtained as follows:

> l2_entries = (cluster_size / sizeof(uint64_t) )
> 
> l2_index = (offset / cluster_size) % l2_entries
> l1_index = (offset / cluster_size) / l2_entries
> 
> l2_table = load_cluster(l1_table[l1_index]);
> cluster_offset = l2_table[l2_index];
> 
> return cluster_offset + (offset % cluster_size)

if  virtual disk offset = 1M, cluster_size = 64K
> l2_entries = cluster_size / 8 = 8KB
> **l2_index = 16 % 8K = 16**
> l1_index = 16 / 8K = 0
> **a L1 entry can handle 8K * 64KB =  512MB data**
> get the 16'd L2 entry in L2 table


if  virtual disk offset = 99M - 512, cluster_size = 64K
> l2_entries = cluster_size / 8 = 8KB
> **l2_index = 1583 % 8K = 1583**
> l1_index = 1583 / 8K = 0
> 
> 1. get the 1583'd L2 entry in L2 table
> 2. get cluster_offset from L2 entry
> 3. 0x70000 + (0xFE00) = 0x7FE00


#### L1 table entry (8 bytes)
Bit

 - 0-8:
Reserved (set to 0)  ????
 - 9-55:
Bits 9-55 of **the offset into the image file at which the L2 table start**. Must be aligned to a cluster boundary. If the offset is 0, the L2 table and all clusters described by this L2 table are unallocated.
 - 56-62:
Reserved (set to 0)
 - 63:
0 for an L2 table that is **unused or requires COW**, 1 if its refcount is exactly one. This information is only accurate in the active L1 table.

> Given L1 table offset is 0x30000
> 0x80, 00000000040000
> L2 offset = 0x40000

#### L2 table entry (8 bytes)

Bit

 - 0-61:
Cluster descriptor
 - 62:
0 for standard clusters
1 for compressed clusters
 - 63:
0 for a cluster that is **unused or requires COW**, 1 if its refcount is exactly one. This information is only accurate in L2 tables that are reachable form the active L1 table.

> a L2 table entry at 0x40000
> 10000000B,  0x00000000050000

#### Standard Cluster Descriptor (62 bits)

BIt

 - 0:
If set to 1, the cluster reads as all zeros. The host cluster offset can be used to describe a preallocation, but it won't be used for reading data from this cluster, nor is data read from the backing file if the cluster is unallocated.
 - 1-8:
Reserved (set to 0)
 - 9-55:
Bits 9-55 of host cluster offset. Must be aligned to a cluster boundary. If the offset is 0, the cluster is unallocated.
 - 56-61:
Reserved (set to 0)

> bit 0-55
> 0x00000000050000


#### Compressed Clusters
...


### Snapshots

qcow2 supports internal snapshots. Their basic principle of operation is **to switch the active L1 table**, so that a different set of host clusters are exposed to the guest.

When creating a snapshot, the L1 table should be copied and **the refcount of all L2 tables and clusters reachable from this L1 table must be increased**, so that **a write causes a COW** and isn't visible in other snapshots.

When loading a snapshot, bit 63 of all entries in the new active L1 table and all L2 tables referenced by it **must be reconstructed** from the refcount table as it doesn't need to be accurate in inactive L1 tables.

A directory of all snapshots is **stored in the snapshot table**, a contiguous area in the image file, whose starting **offset and length are given by the header** fields snapshots_offset and nb_snapshot. The entries of the snapshot table have variable length, depending on the length of ID, name and extra data.

``` c
typedef struct QEMU_PACKED QCowSnapshotHeader {
    /* header is 8 byte aligned */
    uint64_t l1_table_offset;

    uint32_t l1_size;
    uint16_t id_str_size;
    uint16_t name_size;

    uint32_t date_sec;
    uint32_t date_nsec;

    uint64_t vm_clock_nsec;

    uint32_t vm_state_size;
    uint32_t extra_data_size; /* for extension */
    /* extra data follows */
    /* id_str follows */
    /* name follows  */
} QCowSnapshotHeader;
```


### QEMU Cache

default cache size is 1M

cache mode

+ none
	+ host do not do cache, guest disk cache is wb. 
+ writeback
	+ host do read/write cache, guest disk cache is writeback
+ writethrough
	+ host do read cache, guest disk cache is writethrough.
+ unsafe
	+ host do not flush cache, guest disk cache is writeback
+ directsync
	+ host do not do cache, guest disk cache is writethrough
``` c
/**
 * Set open flags for a given cache mode
 *
 * Return 0 on success, -1 if the cache mode was invalid.
 */

/*
 * BDRV_O_NOCACHE: host end 繞過 cache
 * BDRV_O_CACHE_WB: guest 啟用 writeback cache
 * BDRV_O_NO_FLUSH: host end 不同步 cache
 */
int bdrv_parse_cache_flags(const char *mode, int *flags)
{
    *flags &= ~BDRV_O_CACHE_MASK;
 
    if (!strcmp(mode, "off") || !strcmp(mode, "none")) {
        *flags |= BDRV_O_NOCACHE | BDRV_O_CACHE_WB;
        // host no cache, guest has wb cache
    } else if (!strcmp(mode, "directsync")) {
        *flags |= BDRV_O_NOCACHE;
        // host and guest no cache
    } else if (!strcmp(mode, "writeback")) {
        *flags |= BDRV_O_CACHE_WB;
        // host and guest has wb cache
    } else if (!strcmp(mode, "unsafe")) {
        *flags |= BDRV_O_CACHE_WB;
        *flags |= BDRV_O_NO_FLUSH;
        // host 不 flush cache, guest 有 cache
    } else if (!strcmp(mode, "writethrough")) {
        /* this is the default */
        // host 有 cache, guest 沒有
    } else {
        return -1;
    }
 
    return 0;
}
```

#### LVM + qcow2
 Thin Provision
http://mathslinux.org/?p=379



### Snapshot

``` c
typedef struct QEMU_PACKED QCowSnapshotHeader {
    /* header is 8 byte aligned */
    uint64_t l1_table_offset;

    uint32_t l1_size;
    uint16_t id_str_size;
    uint16_t name_size;

    uint32_t date_sec;
    uint32_t date_nsec;

    uint64_t vm_clock_nsec;

    uint32_t vm_state_size;
    uint32_t extra_data_size; /* for extension */
    /* extra data follows */
    /* id_str follows */
    /* name follows  */
} QCowSnapshotHeader;
```


### QEMUFile

defined in migration/qemu-file-internal.h
``` c
struct QEMUFile {
    const QEMUFileOps *ops;

	/* assign BlockDriverState */
    void *opaque;

    int64_t bytes_xfer;
    int64_t xfer_limit;

    int64_t pos; /* start of buffer when writing, end of buffer
                    when reading */
    int buf_index;
    int buf_size; /* 0 when writing */
    uint8_t buf[IO_BUF_SIZE];

    struct iovec iov[MAX_IOV_SIZE];
    unsigned int iovcnt;

    int last_error;
};
```

defined in migration/savevm.c
``` c
/* savevm/loadvm support */

static ssize_t block_writev_buffer(void *opaque, struct iovec *iov, int iovcnt,
                                   int64_t pos)
{
    int ret;
    QEMUIOVector qiov;

    qemu_iovec_init_external(&qiov, iov, iovcnt);
    ret = bdrv_writev_vmstate(opaque, &qiov, pos);
    if (ret < 0) {
        return ret;
    }

    return qiov.size;
}

static ssize_t block_put_buffer(void *opaque, const uint8_t *buf,
                                int64_t pos, size_t size)
{
    bdrv_save_vmstate(opaque, buf, pos, size);
    return size;
}

static ssize_t block_get_buffer(void *opaque, uint8_t *buf, int64_t pos,
                                size_t size)
{
    return bdrv_load_vmstate(opaque, buf, pos, size);
}

static int bdrv_fclose(void *opaque)
{
    return bdrv_flush(opaque);
}

static const QEMUFileOps bdrv_read_ops = {
    .get_buffer = block_get_buffer,
    .close =      bdrv_fclose
};

static const QEMUFileOps bdrv_write_ops = {
    .put_buffer     = block_put_buffer,
    .writev_buffer  = block_writev_buffer,
    .close          = bdrv_fclose
};

static QEMUFile *qemu_fopen_bdrv(BlockDriverState *bs, int is_writable)
{
    if (is_writable) {
        return qemu_fopen_ops(bs, &bdrv_write_ops);
    }
    return qemu_fopen_ops(bs, &bdrv_read_ops);
}
```

defined in block/block_int.h
``` c
struct BlockDriverState {
    int64_t total_sectors; /* if we are reading a disk image, give its
                              size in sectors */
    int read_only; /* if true, the media is read only */
    int open_flags; /* flags used to open the file, re-used for re-open */
    int encrypted; /* if true, the media is encrypted */
    int valid_key; /* if true, a valid encryption key has been set */
    int sg;        /* if true, the device is a /dev/sg* */
    int copy_on_read; /* if true, copy read backing sectors into image
                         note this is a reference count */
    bool probed;

    BlockDriver *drv; /* NULL means no media */
    void *opaque;

    BlockBackend *blk;          /* owning backend, if any */

    AioContext *aio_context; /* event loop used for fd handlers, timers, etc */
    /* long-running tasks intended to always use the same AioContext as this
     * BDS may register themselves in this list to be notified of changes
     * regarding this BDS's context */
    QLIST_HEAD(, BdrvAioNotifier) aio_notifiers;

    char filename[PATH_MAX];
    char backing_file[PATH_MAX]; /* if non zero, the image is a diff of
                                    this file image */
    char backing_format[16]; /* if non-zero and backing_file exists */

    QDict *full_open_options;
    char exact_filename[PATH_MAX];

    BlockDriverState *backing_hd;
    BdrvChild *backing_child;
    BlockDriverState *file;

    NotifierList close_notifiers;

    /* Callback before write request is processed */
    NotifierWithReturnList before_write_notifiers;

    /* number of in-flight serialising requests */
    unsigned int serialising_in_flight;

    /* I/O throttling */
    CoQueue      throttled_reqs[2];
    bool         io_limits_enabled;
    /* The following fields are protected by the ThrottleGroup lock.
     * See the ThrottleGroup documentation for details. */
    ThrottleState *throttle_state;
    ThrottleTimers throttle_timers;
    unsigned       pending_reqs[2];
    QLIST_ENTRY(BlockDriverState) round_robin;

    /* I/O stats (display with "info blockstats"). */
    BlockAcctStats stats;

    /* I/O Limits */
    BlockLimits bl;

    /* Whether produces zeros when read beyond eof */
    bool zero_beyond_eof;

    /* Alignment requirement for offset/length of I/O requests */
    unsigned int request_alignment;

    /* the block size for which the guest device expects atomicity */
    int guest_block_size;

    /* do we need to tell the quest if we have a volatile write cache? */
    int enable_write_cache;

    /* NOTE: the following infos are only hints for real hardware
       drivers. They are not used by the block driver */
    BlockdevOnError on_read_error, on_write_error;
    bool iostatus_enabled;
    BlockDeviceIoStatus iostatus;

    /* the following member gives a name to every node on the bs graph. */
    char node_name[32];
    /* element of the list of named nodes building the graph */
    QTAILQ_ENTRY(BlockDriverState) node_list;
    /* element of the list of "drives" the guest sees */
    QTAILQ_ENTRY(BlockDriverState) device_list;
    QLIST_HEAD(, BdrvDirtyBitmap) dirty_bitmaps;
    int refcnt;

    QLIST_HEAD(, BdrvTrackedRequest) tracked_requests;

    /* operation blockers */
    QLIST_HEAD(, BdrvOpBlocker) op_blockers[BLOCK_OP_TYPE_MAX];

    /* long-running background operation */
    BlockJob *job;

    /* The node that this node inherited default options from (and a reopen on
     * which can affect this node by changing these defaults). This is always a
     * parent node of this node. */
    BlockDriverState *inherits_from;
    QLIST_HEAD(, BdrvChild) children;

    QDict *options;
    BlockdevDetectZeroesOptions detect_zeroes;

    /* The error object in use for blocking operations on backing_hd */
    Error *backing_blocker;

    /* threshold limit for writes, in bytes. "High water mark". */
    uint64_t write_threshold_offset;
    NotifierWithReturn write_threshold_notifier;
};
```


#### SaveState

``` c
typedef struct SaveVMHandlers {
    /* This runs inside the iothread lock.  */
    void (*set_params)(const MigrationParams *params, void * opaque);
    SaveStateHandler *save_state;

    void (*cancel)(void *opaque);
    int (*save_live_complete)(QEMUFile *f, void *opaque);

    /* This runs both outside and inside the iothread lock.  */
    bool (*is_active)(void *opaque);

    /* This runs outside the iothread lock in the migration case, and
     * within the lock in the savevm case.  The callback had better only
     * use data that is local to the migration thread or protected
     * by other locks.
     */
    int (*save_live_iterate)(QEMUFile *f, void *opaque);

    /* This runs outside the iothread lock!  */
    int (*save_live_setup)(QEMUFile *f, void *opaque);
    uint64_t (*save_live_pending)(QEMUFile *f, void *opaque, uint64_t max_size);

    LoadStateHandler *load_state;
} SaveVMHandlers;

typedef struct SaveStateEntry {
    QTAILQ_ENTRY(SaveStateEntry) entry;
    char idstr[256];
    int instance_id;
    int alias_id;
    int version_id;
    int section_id;
    SaveVMHandlers *ops;
    const VMStateDescription *vmsd;
    void *opaque;
    CompatEntry *compat;
    int is_ram;
} SaveStateEntry;

typedef struct SaveState {
    QTAILQ_HEAD(, SaveStateEntry) handlers;
    int global_section_id;
    bool skip_configuration;
    uint32_t len;
    const char *name;
} SaveState;

static SaveState savevm_state = {
    .handlers = QTAILQ_HEAD_INITIALIZER(savevm_state.handlers),
    .global_section_id = 0,
    .skip_configuration = false,
};
```

register handlers
register_savevm()

### VMState

``` c
static inline int64_t size_to_l1(BDRVQcow2State *s, int64_t size)
{
    int shift = s->cluster_bits + s->l2_bits;
    return (size + (1ULL << shift) - 1) >> shift;
}

static inline int64_t qcow2_vm_state_offset(BDRVQcow2State *s)
{
    return (int64_t)s->l1_vm_state_index << (s->cluster_bits + s->l2_bits);
}

s->l1_vm_state_index = size_to_l1(s, header.size);
```

> VM state save at qcow2_vm_state_offset()
> =1 << 29 = 0x20000000 = 512M

