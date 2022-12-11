#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/mm_types.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/slab.h>

#define PROCFS_ENTRY_NAME "my_module"
#define KBUF_SIZE 4096


static struct proc_dir_entry *proc_dir_entry;

static int pid = 0;
static int struct_id = 0;


static struct page *vaddr2ppage(struct mm_struct *mm, unsigned long vaddr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	
	pgd = pgd_offset(mm, vaddr);
	if (pgd_none(*pgd)) {
		printk(KERN_ALERT "Address not mapped in pgd\n");
		return NULL;
	}
	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d)) {
		printk(KERN_ALERT "Address not mapped in p4d\n");
		return NULL;
	}
	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud)) {
		printk(KERN_ALERT "Address not mapped in pud\n");
		return NULL;
	}
	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd)) {
		printk(KERN_ALERT "Address not mapped in pmd\n");
		return NULL;
	}
	pte = pte_offset_kernel(pmd, vaddr);
	if (pte_none(*pte)) {
		printk(KERN_ALERT "Address not mapped in pte\n");
		return NULL;
	}

	return pte_page(*pte);
}


static ssize_t copy2buf_page(char __user *ubuf, struct mm_struct *mm_struct)
{
	char *kbuf = kmalloc(KBUF_SIZE, GFP_KERNEL);
        ssize_t entry_size = 0, actual_kbuf_size = 0;
	struct page *page;
        unsigned long nbytes;
	
	struct vm_area_struct *vm_area_struct = mm_struct->mmap;
	unsigned long vm_start = vm_area_struct->vm_start;
	unsigned long vm_end = vm_area_struct->vm_end;

	while (vm_start < vm_end) {
		if (actual_kbuf_size >= KBUF_SIZE - entry_size*2)
			break;
		page = vaddr2ppage(mm_struct, vm_start);
		if (page != NULL) {
			actual_kbuf_size += sprintf(kbuf + actual_kbuf_size, 
				"{vm_flags=%lu vm_start=%lu}\n", page->flags, vm_start);
			if (!entry_size)
				entry_size = actual_kbuf_size;
		}
		vm_start += PAGE_SIZE;
	}

	if (actual_kbuf_size >= KBUF_SIZE - entry_size*2) {
		actual_kbuf_size += sprintf(kbuf + actual_kbuf_size, "... (buffer is over)\n");
	}
	
	nbytes = copy_to_user(ubuf, kbuf, actual_kbuf_size);
	if (nbytes) {
		printk("copy2buf_page: copy_to_user can't copy %lu bytes\n", nbytes);
		return 0;
	}

	return actual_kbuf_size;
}


static ssize_t copy2buf_vm_area_struct(char __user *ubuf, struct mm_struct *mm_struct)
{
	char *kbuf = kmalloc(KBUF_SIZE, GFP_KERNEL);
	ssize_t entry_size = 0, actual_kbuf_size = 0;
	unsigned long nbytes;

	struct vm_area_struct *vm_area_struct = mm_struct->mmap;
	actual_kbuf_size += sprintf(kbuf, "{vm_flags=%lu vm_start=%lu vm_end=%lu}\n",
		vm_area_struct->vm_flags,
		vm_area_struct->vm_start,
		vm_area_struct->vm_end);
	entry_size = actual_kbuf_size;

	while (vm_area_struct->vm_next && actual_kbuf_size < KBUF_SIZE - entry_size*2) {
		vm_area_struct = vm_area_struct->vm_next;
		actual_kbuf_size += sprintf(kbuf + actual_kbuf_size,
			 "{vm_flags=%lu vm_start=%lu vm_end=%lu}\n",
			vm_area_struct->vm_flags,
			vm_area_struct->vm_start,
			vm_area_struct->vm_end);
	}
	if (actual_kbuf_size >= KBUF_SIZE - entry_size*2) {
		actual_kbuf_size += sprintf(kbuf + actual_kbuf_size, "... (buffer is over)\n");
	}
	
	nbytes = copy_to_user(ubuf, kbuf, actual_kbuf_size);
	if (nbytes) {
		printk("copy2buf_vm_area_struct: copy_to_user can't copy %lu bytes\n", nbytes);
		return 0;
	}

	return actual_kbuf_size;
}


static ssize_t proc_read(struct file *file, char __user *ubuf, size_t ubuf_size, loff_t *ppos)
{
	char *kbuf = kmalloc(KBUF_SIZE, GFP_KERNEL);
	ssize_t actual_kbuf_size = 0;

	struct pid *pid_struct;
	struct task_struct *task_struct;
	struct mm_struct *mm_struct;
	
	pid_struct = find_get_pid(pid);
	if (NULL == pid_struct)	{
		printk(KERN_INFO "Process with pid=%d doesn't exist\n", pid);
		actual_kbuf_size = sprintf(kbuf, "Process with pid=%d doesn't exist\n", pid);
		copy_to_user(ubuf, kbuf, actual_kbuf_size);
		return actual_kbuf_size;
	}

	task_struct = pid_task(pid_struct, PIDTYPE_PID);
	if (NULL == task_struct) {
		printk(KERN_INFO "Failed to get task_struct with pid=%d\n", pid);
		actual_kbuf_size = sprintf(kbuf, "Failed to get task_struct with pid=%d\n", pid);
		copy_to_user(ubuf, kbuf, actual_kbuf_size);
		return actual_kbuf_size;
	}

	mm_struct = task_struct->mm;
	if (NULL == mm_struct) {
		printk(KERN_INFO "mm_struct is NULL | pid=%d\n", pid);
                actual_kbuf_size = sprintf(kbuf, "mm_struct is NULL | pid=%d\n", pid);
                copy_to_user(ubuf, kbuf, actual_kbuf_size);
                return actual_kbuf_size;
	}
	
	if (struct_id == 0)
		actual_kbuf_size = copy2buf_page(ubuf, mm_struct);
	else if (struct_id == 1)
		actual_kbuf_size = copy2buf_vm_area_struct(ubuf, mm_struct);

	return actual_kbuf_size;
}


static ssize_t proc_write(struct file *file, const char __user *ubuf, size_t ubuf_len, loff_t *offset)
{
	char *kbuf = kmalloc(KBUF_SIZE, GFP_KERNEL);
	int arg1, arg2, args_num;
	
	unsigned long nbytes = copy_from_user(kbuf, ubuf, ubuf_len);
	if (nbytes) {
		printk("proc_write: copy_from_user can't copy %lu bytes\n", nbytes);
		return 0;
	}
	printk(KERN_INFO "proc_write: write %zu bytes\n", ubuf_len);

	args_num = sscanf(kbuf, "%d %d", &arg1, &arg2);
	if (args_num == 2) {
		printk(KERN_INFO "Arguments have been read: arg1 = %d, arg2 = %d\n", arg1, arg2);
		pid = arg1;
		struct_id = arg2;
	}
	else {
		printk(KERN_INFO "sscanf failed: %d argument(s) have been read", args_num);
	}
	
	return ubuf_len;
}


static const struct file_operations proc_fops = {
	.read = proc_read,
	.write = proc_write,
};

static int __init my_module_init(void)
{
        proc_dir_entry = proc_create(PROCFS_ENTRY_NAME, 0, NULL, &proc_fops);
        if (NULL == proc_dir_entry) {
                proc_remove(proc_dir_entry);
                printk(KERN_ALERT "Could not initialize /proc/%s", PROCFS_ENTRY_NAME);
                return ENOMEM;
        }
        printk(KERN_INFO "/proc/%s initialized", PROCFS_ENTRY_NAME);
        return 0;
}


static void __exit my_module_cleanup(void)
{
        proc_remove(proc_dir_entry);
        printk(KERN_INFO "/proc/%s removed", PROCFS_ENTRY_NAME);
}


module_init(my_module_init);
module_exit(my_module_cleanup);


MODULE_LICENSE("GPL");

