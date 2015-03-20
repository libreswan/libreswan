#ifndef _NFSIM_PROC_STUFF_H
#define _NFSIM_PROC_STUFF_H

#define FMODE_READ 1
#define FMODE_WRITE 2

struct inode {
	int i_mode;
	struct proc_dir_entry *e;
};

struct dentry {
	struct inode *d_inode;
};

struct file {
	int f_mode;
	struct dentry *f_dentry;
	loff_t f_pos;
	void *private_data;
};

/* proc_fs.h */
struct file;
typedef int (read_proc_t)(char *page, char **start, off_t off,
			  int count, int *eof, void *data);
typedef int (write_proc_t)(struct file *file, const char *buffer,
			   unsigned long count, void *data);
typedef int (get_info_t)(char *, char **, off_t, int);

struct proc_dir_entry {
	unsigned short namelen;
	const char *name;
	get_info_t *get_info;
	struct module *owner;
	struct proc_dir_entry *next, *parent, *subdir;
	struct file_operations *proc_fops;
	void *data;
	read_proc_t *read_proc;
	write_proc_t *write_proc;

	/* all we need is the S_IFDR flag.. */
	mode_t mode;
};

extern struct proc_dir_entry proc_root, *proc_net, *proc_net_stat;

int proc_match(int len, const char *name, struct proc_dir_entry *de);
struct proc_dir_entry *proc_mkdir(const char *name,
				  struct proc_dir_entry *parent);

struct proc_dir_entry *create_proc_entry(const char *name, mode_t mode,
					 struct proc_dir_entry *parent);

void remove_proc_entry(const char *name, struct proc_dir_entry *parent);

extern struct proc_dir_entry *create_proc_info_entry(const char *name,
						     mode_t mode,
						     struct proc_dir_entry *base,
						     get_info_t *get_info);

extern struct proc_dir_entry *proc_net_create(const char *name, mode_t mode,
					      get_info_t *get_info);

extern struct proc_dir_entry *proc_net_fops_create(const char *name,
						   mode_t mode,
						   struct file_operations *fops);

extern void proc_net_remove(const char *name);

/* fs.h */
struct file_operations {
	struct module *owner;
	loff_t (*llseek) (struct file *, loff_t, int);
	ssize_t (*read) (struct file *, char *, size_t, loff_t *);
	int (*open) (struct inode *, struct file *);
	int (*release) (struct inode *, struct file *);
	ssize_t (*write) (struct file *, const char __user *, size_t,
			  loff_t *);
};

/* seq_file.h */
struct seq_file {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	loff_t index;
	struct semaphore sem;
	struct seq_operations *op;
	void *private;
};

struct seq_operations {
	void * (*start) (struct seq_file *m, loff_t *pos);
	void (*stop) (struct seq_file *m, void *v);
	void * (*next) (struct seq_file *m, void *v, loff_t *pos);
	int (*show) (struct seq_file *m, void *v);
};

#define FMODE_PREAD     8
#define FMODE_PWRITE    FMODE_PREAD     /* These go hand in hand */

int seq_open(struct file *, struct seq_operations *);
ssize_t seq_read(struct file *, char *, size_t, loff_t *);
loff_t seq_lseek(struct file *, loff_t, int);
int seq_release(struct inode *, struct file *);
int seq_escape(struct seq_file *, const char *, const char *);
int seq_putc(struct seq_file *m, char c);
int seq_puts(struct seq_file *m, const char *s);

int seq_printf(struct seq_file *, const char *, ...)
__attribute__ ((format(printf, 2, 3)));

int single_open(struct file *, int (*)(struct seq_file *, void *), void *);
int single_release(struct inode *, struct file *);
int seq_release_private(struct inode *, struct file *);

#define SEQ_START_TOKEN ((void *)1)

/* proc_fs.h */
struct proc_dir_entry *PDE(const struct inode *inode);

/*
 * sysctl.h: General linux system control interface
 *
 * Begun 24 March 1995, Stephen Tweedie
 *
 ****************************************************************
 ****************************************************************
 **
 **  The values in this file are exported to user space via
 **  the sysctl() binary interface.  However this interface
 **  is unstable and deprecated and will be removed in the future.
 **  For a stable interface use /proc/sys.
 **
 ****************************************************************
 ****************************************************************
 */

/* Define sysctl names first */

/* Top-level names: */

/* For internal pattern-matching use only: */
#define CTL_ANY         -1      /* Matches any name */
#define CTL_NONE        0

enum {
	CTL_KERN=1,             /* General kernel info and control */
	CTL_VM=2,               /* VM management */
	CTL_NET=3,              /* Networking */
	CTL_PROC=4,             /* Process info */
	CTL_FS=5,               /* Filesystems */
	CTL_DEBUG=6,            /* Debugging */
	CTL_DEV=7,              /* Devices */
	CTL_BUS=8,              /* Busses */
	CTL_ABI=9,              /* Binary emulation */
	CTL_CPU=10              /* CPU stuff (speed scaling, etc) */
};

/* CTL_NET names: */
enum {
	NET_CORE=1,
	NET_ETHER=2,
	NET_802=3,
	NET_UNIX=4,
	NET_IPV4=5,
	NET_IPX=6,
	NET_ATALK=7,
	NET_NETROM=8,
	NET_AX25=9,
	NET_BRIDGE=10,
	NET_ROSE=11,
	NET_IPV6=12,
	NET_X25=13,
	NET_TR=14,
	NET_DECNET=15,
	NET_ECONET=16,
	NET_SCTP=17,
};

/* /proc/sys/net/core */
enum {
	NET_CORE_WMEM_MAX=1,
	NET_CORE_RMEM_MAX=2,
	NET_CORE_WMEM_DEFAULT=3,
	NET_CORE_RMEM_DEFAULT=4,
/* was	NET_CORE_DESTROY_DELAY */
	NET_CORE_MAX_BACKLOG=6,
	NET_CORE_FASTROUTE=7,
	NET_CORE_MSG_COST=8,
	NET_CORE_MSG_BURST=9,
	NET_CORE_OPTMEM_MAX=10,
	NET_CORE_HOT_LIST_LENGTH=11,
	NET_CORE_DIVERT_VERSION=12,
	NET_CORE_NO_CONG_THRESH=13,
	NET_CORE_NO_CONG=14,
	NET_CORE_LO_CONG=15,
	NET_CORE_MOD_CONG=16,
	NET_CORE_DEV_WEIGHT=17,
	NET_CORE_SOMAXCONN=18,
};

/* /proc/sys/net/ipv4 */
enum {
	/* v2.0 compatibile variables */
	NET_IPV4_FORWARD=8,
	NET_IPV4_DYNADDR=9,

	NET_IPV4_CONF=16,
	NET_IPV4_NEIGH=17,
	NET_IPV4_ROUTE=18,
	NET_IPV4_FIB_HASH=19,
	NET_IPV4_NETFILTER=20,
};

/* /proc/sys/net/ipv4/netfilter */
enum {
	NET_IPV4_NF_CONNTRACK_MAX=1,
	NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_SYN_SENT=2,
	NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_SYN_RECV=3,
	NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_ESTABLISHED=4,
	NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_FIN_WAIT=5,
	NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_CLOSE_WAIT=6,
	NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_LAST_ACK=7,
	NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_TIME_WAIT=8,
	NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_CLOSE=9,
	NET_IPV4_NF_CONNTRACK_UDP_TIMEOUT=10,
	NET_IPV4_NF_CONNTRACK_UDP_TIMEOUT_STREAM=11,
	NET_IPV4_NF_CONNTRACK_ICMP_TIMEOUT=12,
	NET_IPV4_NF_CONNTRACK_GENERIC_TIMEOUT=13,
	NET_IPV4_NF_CONNTRACK_BUCKETS=14,
	NET_IPV4_NF_CONNTRACK_LOG_INVALID=15,
	NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_MAX_RETRANS=16,
	NET_IPV4_NF_CONNTRACK_TCP_LOOSE=17,
	NET_IPV4_NF_CONNTRACK_TCP_BE_LIBERAL=18,
	NET_IPV4_NF_CONNTRACK_TCP_MAX_RETRANS=19,
	NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_CLOSED=20,
	NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_WAIT=21,
	NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_ECHOED=22,
	NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_ESTABLISHED=23,
	NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_SENT=24,
	NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_RECD=25,
	NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_ACK_SENT=26,
	NET_IPV4_NF_CONNTRACK_COUNT=27,
};

/* CTL_PROC names: */
extern void sysctl_init(void);

typedef struct ctl_table ctl_table;

typedef int ctl_handler (ctl_table *table, int *name, int nlen,
			 void *oldval, size_t *oldlenp,
			 void *newval, size_t newlen,
			 void **context);

typedef int proc_handler (ctl_table *ctl, int write, struct file * filp,
			  void *buffer, size_t *lenp, loff_t *ppos);

extern int proc_dostring(ctl_table *, int, struct file *,
			 void *, size_t *, loff_t *);
extern int proc_dointvec(ctl_table *, int, struct file *,
			 void *, size_t *, loff_t *);
extern int proc_dointvec_bset(ctl_table *, int, struct file *,
			      void *, size_t *, loff_t *);
extern int proc_dointvec_minmax(ctl_table *, int, struct file *,
				void *, size_t *, loff_t *);
extern int proc_dointvec_jiffies(ctl_table *, int, struct file *,
				 void *, size_t *, loff_t *);
extern int proc_dointvec_userhz_jiffies(ctl_table *, int, struct file *,
					void *, size_t *, loff_t *);
extern int proc_doulongvec_minmax(ctl_table *, int, struct file *,
				  void *, size_t *, loff_t *);
extern int proc_doulongvec_ms_jiffies_minmax(ctl_table *table, int,
					     struct file *, void *, size_t *,
					     loff_t *);

extern int do_sysctl(int *name, int nlen,
		     void *oldval, size_t *oldlenp,
		     void *newval, size_t newlen);

extern int do_sysctl_strategy(ctl_table *table,
			      int *name, int nlen,
			      void *oldval, size_t *oldlenp,
			      void *newval, size_t newlen, void ** context);

extern ctl_handler sysctl_string;
extern ctl_handler sysctl_intvec;
extern ctl_handler sysctl_jiffies;

/*
 * Register a set of sysctl names by calling register_sysctl_table
 * with an initialised array of ctl_table's.  An entry with zero
 * ctl_name terminates the table.  table->de will be set up by the
 * registration and need not be initialised in advance.
 *
 * sysctl names can be mirrored automatically under /proc/sys.  The
 * procname supplied controls /proc naming.
 *
 * The table's mode will be honoured both for sys_sysctl(2) and
 * proc-fs access.
 *
 * Leaf nodes in the sysctl tree will be represented by a single file
 * under /proc; non-leaf nodes will be represented by directories.  A
 * null procname disables /proc mirroring at this node.
 *
 * sysctl(2) can automatically manage read and write requests through
 * the sysctl table.  The data and maxlen fields of the ctl_table
 * struct enable minimal validation of the values being written to be
 * performed, and the mode field allows minimal authentication.
 *
 * More sophisticated management can be enabled by the provision of a
 * strategy routine with the table entry.  This will be called before
 * any automatic read or write of the data is performed.
 *
 * The strategy routine may return:
 * <0: Error occurred (error is passed to user process)
 * 0:  OK - proceed with automatic read or write.
 * >0: OK - read or write has been done by the strategy routine, so
 *     return immediately.
 *
 * There must be a proc_handler routine for any terminal nodes
 * mirrored under /proc/sys (non-terminals are handled by a built-in
 * directory handler).  Several default handlers are available to
 * cover common cases.
 */

/* A sysctl table is an array of struct ctl_table: */
struct ctl_table {
	int ctl_name;                   /* Binary ID */
	const char *procname;           /* Text ID for /proc/sys, or zero */
	void *data;
	int maxlen;
	mode_t mode;
	ctl_table *child;
#ifdef CTL_TABLE_PARENT
	ctl_table *parent;
#endif
	proc_handler *proc_handler;     /* Callback for text formatting */
	ctl_handler *strategy;          /* Callback function for all r/w */
	struct proc_dir_entry *de;      /* /proc control block */
	void *extra1;
	void *extra2;
};

struct ctl_table_header;

struct ctl_table_header * register_sysctl_table(ctl_table * table,
						int insert_at_head);
void unregister_sysctl_table(struct ctl_table_header * table);

/* sysctl variables */
extern int sysctl_ip_default_ttl;

#endif /* _NFSIM_PROC_STUFF_H */
