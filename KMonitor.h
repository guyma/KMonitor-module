#include <linux/mutex.h>                 /// Required for the mutex functionality
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <asm/cacheflush.h>
#include <linux/syscalls.h>
#include <linux/delay.h> 
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/file.h>
#include <linux/fs.h> 
#include <linux/fs_struct.h>
#include <linux/proc_fs.h>
#include <linux/fdtable.h>    // for files_fdtable(..)
#include <linux/vmalloc.h>
#include <linux/time.h>
#include <linux/timekeeping.h>
#include <linux/rtc.h>


// Write Protect Bit (CR0:16)
#define PROCFS_NAME		        "KMonitor"
#define MAX_HISTORY                     10
#define LINE_LENGTH                     200
#define PROCFS_READ_BUFFER_SIZE         LINE_LENGTH * (MAX_HISTORY + 5) // +5 for the head lines and configuratins
#define PROCFS_MAX_SIZE		        1024

/// results in a semaphore variable history_mutex with value 1 (unlocked)
/// A macro that is used to declare a new mutex that is visible in this file
static DEFINE_MUTEX(history_mutex);  


// Write Protect Bit (CR0:16)
#define CR0_WP 0x00010000 

// Global Variables
unsigned long orig_cr0;

static void **syscall_table;
static char tmp_line[LINE_LENGTH];
static char procfs_read_buf[PROCFS_READ_BUFFER_SIZE];
static char filemon_set = 0;
static char netmon_set = 0;
static char mountmon_set = 0;

// Internal Functions
static unsigned long **find_sys_call_table(void);
static void exchange_table(void);
static void exchange_table_back(void);
static char *get_exe_path_parent(char *path_buf);
static void addhistory(char *src);
static ssize_t procfile_write(struct file *file, const char __user *buffer, size_t length, loff_t *data);
static ssize_t procfile_read(struct file *file, char *buffer, size_t length, loff_t *offset);

// Procfs definitions
static struct file_operations cmd_file_ops = {
    .owner = THIS_MODULE,
    .read = procfile_read,
    .write = procfile_write,
};
struct proc_dir_entry *Our_Proc_File;
// The buffer used to store character for this module
static char procfs_buffer[PROCFS_MAX_SIZE];
// The size of the buffer wheich we use int the procfile_write 
static unsigned long procfs_buffer_size = 0;

struct history_struct {
    int head;
    int tail;
    int total;
    char history[MAX_HISTORY][LINE_LENGTH];
};
static struct history_struct km_history;

// Pointers to store the original system calls
long (*orig_sys_open)(const char __user *pathname, int flags, umode_t mode);
long (*orig_sys_read)(unsigned int fd, char __user *buf, size_t count);
long (*orig_sys_write)(unsigned int fd, const char __user *buf, size_t count);
long (*orig_sys_listen)(int, int);
long (*orig_sys_accept)(int, struct sockaddr __user *, int __user *);
long (*orig_sys_mount)(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data);

