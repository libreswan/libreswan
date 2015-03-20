#include <kernelenv.h>
#include <linux/sysctl.h>

extern int proc_dostring(ctl_table *, int, struct file *,
			 void __user *, size_t *, loff_t *);
extern int proc_dointvec(ctl_table *, int, struct file *,
			 void __user *, size_t *, loff_t *);
extern int proc_dointvec_bset(ctl_table *, int, struct file *,
			      void __user *, size_t *, loff_t *);
extern int proc_dointvec_minmax(ctl_table *, int, struct file *,
				void __user *, size_t *, loff_t *);
extern int proc_dointvec_jiffies(ctl_table *, int, struct file *,
				 void __user *, size_t *, loff_t *);
extern int proc_dointvec_userhz_jiffies(ctl_table *, int, struct file *,
					void __user *, size_t *, loff_t *);
extern int proc_dointvec_ms_jiffies(ctl_table *, int, struct file *,
				    void __user *, size_t *, loff_t *);
extern int proc_doulongvec_minmax(ctl_table *, int, struct file *,
				  void __user *, size_t *, loff_t *);
extern int proc_doulongvec_ms_jiffies_minmax(ctl_table *table, int,
					     struct file *, void __user *,
					     size_t *, loff_t *);

int proc_dostring(ctl_table *t, int a, struct file *b,
		  void __user *c, size_t *d, loff_t *f)
{
	return 0;
}

int proc_dointvec(ctl_table *t, int a, struct file *b,
		  void __user *c, size_t *d, loff_t *f)
{
	return 0;
}

int proc_dointvec_bset(ctl_table *t, int a, struct file *b,
		       void __user *c, size_t *d, loff_t *f)
{
	return 0;
}

int proc_dointvec_minmax(ctl_table *t, int a, struct file *b,
			 void __user *c, size_t *d, loff_t *f)
{
	return 0;
}

int proc_dointvec_jiffies(ctl_table *t, int a, struct file *b,
			  void __user *c, size_t *d, loff_t *f)
{
	return 0;
}

int proc_dointvec_userhz_jiffies(ctl_table *t, int a, struct file *b,
				 void __user *c, size_t *d, loff_t *f)
{
	return 0;
}

int proc_dointvec_ms_jiffies(ctl_table *t, int a, struct file *b,
			     void __user *c, size_t *d, loff_t *f)
{
	return 0;
}

int proc_doulongvec_minmax(ctl_table *t, int a, struct file *b,
			   void __user *c, size_t *d, loff_t *f)
{
	return 0;
}

int proc_doulongvec_ms_jiffies_minmax(ctl_table *table, int a,
				      struct file *b,
				      void __user *c, size_t *d, loff_t *f)
{
	return 0;
}

