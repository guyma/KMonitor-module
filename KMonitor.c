#include "KMonitor.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Guy Malul");
MODULE_DESCRIPTION("Cyber Security Defense of Linux Based Operating Systems");

/**
 * Every hooked system call add her printk to the history struct
 * history holds up to last 10 events
 * the buffer is cyclic
 * km_history->head the 1th printk
 * km_history->tail the last printk
 * 
 * this function is protected by the lock: - history_mutex -
 */
static void addhistory(char *src)
{
    char *dst;
    
    if(km_history.total >= MAX_HISTORY)
        km_history.head = (km_history.head + 1) % MAX_HISTORY;
    else
        km_history.total++;
    
    dst = &km_history.history[km_history.tail][0];
    
    // copy the current history line to the km_history buffer
    strncpy(dst, src, LINE_LENGTH);
    
    km_history.tail = (km_history.tail + 1) % MAX_HISTORY;
}

/**
 * Look for the system call table between 2 known address
 * in this specific kernel:
 * /boot/System.map-3.19.0-25-generic
 *
 * ffffffff811e99c0 T sys_close
 * ffffffff81801460 R sys_call_table
 * ffffffff81c1d070 D loops_per_jiffy
 *
 */

static unsigned long **find_sys_call_table()
{
    unsigned long ptr;
    unsigned long *p;
    
    for (ptr = (unsigned long) sys_close; ptr < (unsigned long) &loops_per_jiffy; ptr += sizeof(void *))
    {
        
        p = (unsigned long *) ptr;
        
        if (p[__NR_close] == (unsigned long) sys_close)
        {
            return (unsigned long **) p;
        }
    }
    
    return NULL;
}

/**
 * Getting the file name of a given file descriptor, 
 * from the current process files table
 * explenation on fget/fput: http://stackoverflow.com/questions/12751167/what-does-fget-light-in-linux-work
 * 
 * using fget and fput according to the kernel convention
 */
static char* get_filename_by_fd(char *filename_buf, int fd)
{  

    struct file *file;
    
    struct path *file_path;
    char *pathname;
     try_module_get(THIS_MODULE);

    file = fget(fd);
    
    if(!file)
        return 0;
    
    file_path = &file->f_path;
    
    fput(file);
    
    path_get(file_path);
    pathname = d_path(file_path,filename_buf, PATH_MAX);
    path_put(file_path);
    if (IS_ERR(pathname)) {
        return 0;/*PTR_ERR(pathname);*/
    }
    module_put(THIS_MODULE);
    return pathname;
}

/** 
 * Getting the full path of the file that
 * exectutes the system call we track
 */
static char *get_exe_path(char *path_buf)
{
    

    char *p_res = 0;
    struct mm_struct* mm;
    
    try_module_get(THIS_MODULE);

    mm = current->mm;
    if(mm){
        down_read(&mm->mmap_sem);
        
        if (mm->exe_file)
            p_res = d_path(&mm->exe_file->f_path, path_buf, PATH_MAX);
        
        up_read(&mm->mmap_sem);
    } // if(mm)
    
    module_put(THIS_MODULE);

    return p_res;
}


/** 
 * Getting the full path of the program that
 * exectutes the process that make the system call we track 
 * example: used in mount
 */
static char *get_exe_path_parent(char *path_buf)
{
    

    
    char *p_res = 0;
    struct mm_struct* mm;
    try_module_get(THIS_MODULE);

    mm = current->parent->mm;
    if(mm){
        down_read(&mm->mmap_sem);
        
        if (mm->exe_file)
            p_res = d_path(&mm->exe_file->f_path, path_buf, PATH_MAX);
        
        up_read(&mm->mmap_sem);
    } // if(mm)
    
    module_put(THIS_MODULE);

    return p_res;
}

// Hooking the system call SYS_OPEN
static asmlinkage long my_sys_open(const char __user *pathname, int flags, mode_t mode)
{
    try_module_get(THIS_MODULE);

    if(filemon_set){
        char *exe_path_buf, *p_to_exe_buf;
        // history time  print
        struct rtc_time result;
        struct timeval time;
        unsigned long local_time;
        
        // malloc the buffer for the executable path string
        exe_path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
        if(!exe_path_buf){
            printk(KERN_DEBUG "KMonitor_Open_Error: kmalloc for exe_path_buf failed\n");
            goto out;
        }
        
        // fill the buff with the path string, p_to_exe_buf = pointer to where the string start
        p_to_exe_buf = get_exe_path(exe_path_buf);
        if(!p_to_exe_buf){
            printk(KERN_DEBUG "KMonitor_Open_Error: get_exe_path(exe_path_buf) failed\n");
            kfree(exe_path_buf);
            goto out;
        }
        printk(KERN_DEBUG "%s (pid: %d) is opening %s\n", p_to_exe_buf, task_tgid_vnr(current),  pathname);
        
        // History & Time 
        do_gettimeofday(&time);
        local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
        rtc_time_to_tm(local_time, &result);
        
        snprintf(tmp_line, LINE_LENGTH,
                 "%d/%d/%d %.2d:%.2d:%.2d, %s (pid: %d) is opening %s\n", 
                 result.tm_mday, (result.tm_mon+1), (result.tm_year+1900), (result.tm_hour), (result.tm_min), (result.tm_sec),
                 p_to_exe_buf, task_tgid_vnr(current),  pathname);
        
        mutex_lock(&history_mutex);
        addhistory(tmp_line);
        mutex_unlock(&history_mutex);
        
        
        
        
        kfree(exe_path_buf);
    } // if(filemon_set)
    out:
    module_put(THIS_MODULE);

    return orig_sys_open(pathname, flags, mode);
}

/*
 * For every call to sys_read, print:
 * - file name
 * - pid
 * - the full path of the executable that read the file
 * - the amount of bytes have been read
 */
// Still having problems 
// Hooking the system call SYS_READ
static asmlinkage long my_sys_read(unsigned int fd, char __user *buf, size_t count)
{
    if (!try_module_get(THIS_MODULE))
        return -1;


    if(filemon_set){
        // for the full path of the executable that read the file
        // p_to_buf is the ptr return from d_path, some times the path is not from the
        // start of path_buf, and the start is feel with 00000
        char *path_buf, *p_to_buf, *filename_buf, *p_to_filename_buf;
        int curr_pid;
        // history time  print
        struct rtc_time result;
        struct timeval time;
        unsigned long local_time;
        
        
        path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
        if(!path_buf){
            printk(KERN_DEBUG "KMonitor_Error: kmalloc for path_buf failed\n");
            goto out;
        }
        
        p_to_buf = get_exe_path(path_buf);
        
        if(!p_to_buf){
            printk(KERN_DEBUG "KMonitor_Error: get_exe_path(path_buf) failed\n");
            kfree(path_buf);
            goto out;
        }
        
        filename_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
        if(!filename_buf){
            printk(KERN_DEBUG "KMonitor_Error: kmalloc for filename_buf failed\n");
            kfree(path_buf);
            goto out;
        }
        
        p_to_filename_buf = get_filename_by_fd(filename_buf, fd);
        if(!p_to_filename_buf){
            printk(KERN_DEBUG "KMonitor_Error: get_filename_by_fd(filename_buf, fd) failed\n");
            kfree(path_buf);
            kfree(filename_buf);
            goto out;
        }
        
        curr_pid = task_tgid_vnr(current);
        printk(KERN_DEBUG "%s (pid: %d) is readind %ld bytes from %s\n",p_to_buf, curr_pid, count, p_to_filename_buf);
        
        // History & Time 
        do_gettimeofday(&time);
        local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
        rtc_time_to_tm(local_time, &result);
        
        snprintf(tmp_line, LINE_LENGTH,
                 "%d/%d/%d %.2d:%.2d:%.2d, %s (pid: %d) is readind %ld bytes from %s\n",
                 result.tm_mday, (result.tm_mon+1), (result.tm_year+1900), (result.tm_hour), (result.tm_min), (result.tm_sec),
                 p_to_buf, curr_pid, count, p_to_filename_buf);
        
        mutex_lock(&history_mutex);
        addhistory(tmp_line);
        mutex_unlock(&history_mutex);
        
        
        kfree(path_buf);
        kfree(filename_buf);
        
    }// if    
    out:
    module_put(THIS_MODULE);

    return orig_sys_read(fd, buf, count);
}

// Hooking the system call SYS_WRITE
static asmlinkage long my_sys_write(unsigned int fd, const char __user *buf, size_t count)
{
    if (!try_module_get(THIS_MODULE))
        return -1;

    if(filemon_set){
        
        int curr_pid;
        char *exe_path_buf, *p_to_exe_buf, *filename_buf, *p_to_filename_buf;
        // history time  print
        struct rtc_time result;
        struct timeval time;
        unsigned long local_time;

        // malloc the buffer for the executable path string
        exe_path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
        if(!exe_path_buf){
            printk(KERN_DEBUG "KMonitor_Write_Error: kmalloc for exe_path_buf failed\n");
            goto out;
        }
        // fill the buff with the path string
        // p_to_exe_buf = pointer to where the string start
        p_to_exe_buf = get_exe_path(exe_path_buf);
        if(!p_to_exe_buf){
            printk(KERN_DEBUG "KMonitor_Write_Error: get_exe_path(exe_path_buf) failed\n");
            kfree(exe_path_buf);
            goto out;
        }
        // malloc the buffer for the filename string of the file we write to
        filename_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
        if(!filename_buf){
            printk(KERN_DEBUG "KMonitor_Write_Error: kmalloc for filename_buf failed\n");
            kfree(exe_path_buf);
            goto out;
        }
        // fill the buff with the path string
        // p_to_filename_buf = pointer to where the string start
        p_to_filename_buf = get_filename_by_fd(filename_buf, fd);
        if(!p_to_filename_buf){
            printk(KERN_DEBUG "KMonitor_Write_Error: get_filename_by_fd(filename_buf, fd) failed\n");
            kfree(exe_path_buf);
            kfree(filename_buf);
            goto out;
        }

        
        curr_pid = (int)task_tgid_vnr(current);
        if(exe_path_buf && p_to_exe_buf && filename_buf && p_to_filename_buf)
            printk(KERN_DEBUG "%s (pid: %d) is writing %ld bytes to %s\n",p_to_exe_buf, curr_pid, count, p_to_filename_buf);
        
        // History & Time 
        do_gettimeofday(&time);
        local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
        rtc_time_to_tm(local_time, &result);
        
        snprintf(tmp_line, LINE_LENGTH,
                 "%d/%d/%d %.2d:%.2d:%.2d, %s (pid: %d) is writing %ld bytes to %s\n",
                 result.tm_mday, (result.tm_mon+1), (result.tm_year+1900), (result.tm_hour), (result.tm_min), (result.tm_sec),
                 p_to_exe_buf, curr_pid, count, p_to_filename_buf);
        
        mutex_lock(&history_mutex);
        addhistory(tmp_line);
        mutex_unlock(&history_mutex);
        
        kfree(exe_path_buf);
        kfree(filename_buf);
    }// if(filemon_set)
    
out:
    module_put(THIS_MODULE);

    return orig_sys_write(fd, buf, count);
}

/**
 * Hooking the system call SYS_LISTEN
 * get the socket from fd
 * get proto_ops from the socket
 * use getname function from the proto_ops
 * 
 **/
static asmlinkage long my_sys_listen(int sockfd, int backlog)
{
    if (!try_module_get(THIS_MODULE))
        return -1;

    if(netmon_set){
        char *exe_path_buf, *p_to_exe_buf;
        struct socket *sock;
        struct sockaddr_storage address;			// storage because maybe it's ipv6
        int len, err, ret;
        // history time  print
        struct rtc_time result;
        struct timeval time;
        unsigned long local_time;
        
        ret = orig_sys_listen(sockfd, backlog);
        
        // in case listen failed
        if(ret)
            goto out;
        
        sock = sockfd_lookup(sockfd, &err);					// get the socket by the sockfd
        if (!sock)
            goto out;
        
        err = kernel_getsockname(sock, (struct sockaddr *)&address, &len);
        if(err)	//if err=0 success
            goto out;			// getname failed
            
        // malloc the buffer for the executable path string
        exe_path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
        if(!exe_path_buf){
            printk(KERN_DEBUG "KMonitor_Write_Error: kmalloc for exe_path_buf failed\n");
            goto out;
        }
        // fill the buff with the path string, p_to_exe_buf = pointer to where the string start
        p_to_exe_buf = get_exe_path(exe_path_buf);
        if(!p_to_exe_buf){
            printk(KERN_DEBUG "KMonitor_Write_Error: get_exe_path(exe_path_buf) failed\n");
            kfree(exe_path_buf);
            goto out;
        }
        

        printk(KERN_DEBUG "%s (pid: %d) is listetning on ip: %pISpc\n",p_to_exe_buf, (int)task_tgid_vnr(current), &address); 
        
        // History & Time 
        do_gettimeofday(&time);
        local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
        rtc_time_to_tm(local_time, &result);
        
        snprintf(tmp_line, LINE_LENGTH,
                 "%d/%d/%d %.2d:%.2d:%.2d, %s (pid: %d) is listetning on ip: %pISpc\n",
                 result.tm_mday, (result.tm_mon+1), (result.tm_year+1900), (result.tm_hour), (result.tm_min), (result.tm_sec),
                 p_to_exe_buf, (int)task_tgid_vnr(current), &address);
        
        mutex_lock(&history_mutex);
        addhistory(tmp_line);
        mutex_unlock(&history_mutex);
        

        kfree(exe_path_buf);
        out:
            module_put(THIS_MODULE);

            return ret;
    } // if(netmon_set)
    else 
    {
        module_put(THIS_MODULE);

        return orig_sys_listen(sockfd, backlog);
    }
}

/**
 * Hooking the system call SYS_ACCEPT
 * 
 * Customer PORT
 * Customer Family (ipv6/ipv4)
 * The Server pid 
 * Server executable path
 * 
 */
static asmlinkage long my_sys_accept(int sockfd, struct sockaddr __user *addr, int __user *addrlen)
{ 

    if (!try_module_get(THIS_MODULE))
        return -1;

    if(netmon_set){
        char *path_buf, *p_to_buf;
        struct socket *sock;
        int newfd, err, len, curr_pid;
        struct sockaddr_storage address;
        // history time  print
        struct rtc_time result;
        struct timeval time;
        unsigned long local_time;
        
        newfd = orig_sys_accept(sockfd, addr, addrlen);
        if(newfd < 0)                                                           // Error accept socket
            goto out;
        
        sock = sockfd_lookup(newfd, &err);
        if (!sock)
            goto out;
        
        if(sock->type != SOCK_STREAM)
            goto out;
        
        err = kernel_getpeername(sock, (struct sockaddr *)&address, &len);
        if(err)	                                                                //if err=0 -> success
            goto out;			                                        // getname failed
            
            
        // The path to the executable that runs the Server
        path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
        if(unlikely(!path_buf))
        {
            printk(KERN_DEBUG "KMonitor_Error: kmalloc for path_buf failed\n");
            goto out;
        }
        p_to_buf = get_exe_path(path_buf);
        if(!p_to_buf)
        {
            printk(KERN_DEBUG "KMonitor_Error: get_exe_path(path_buf) failed\n");
            kfree(path_buf);
            goto out;
        }
        
        
        curr_pid = task_tgid_vnr(current);
        printk(KERN_DEBUG "%s (pid: %d) is received a connection from %pISpc\n",p_to_buf, curr_pid, &address); 
        

        // History & Time 
        do_gettimeofday(&time);
        local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
        rtc_time_to_tm(local_time, &result);
        
        snprintf(tmp_line, LINE_LENGTH,
                 "%d/%d/%d %.2d:%.2d:%.2d, %s (pid: %d) is received a connection from %pISpc\n",
                 result.tm_mday, (result.tm_mon+1), (result.tm_year+1900), (result.tm_hour), (result.tm_min), (result.tm_sec),
                 p_to_buf, curr_pid, &address);

        mutex_lock(&history_mutex);
        addhistory(tmp_line);
        mutex_unlock(&history_mutex);
        
        kfree(path_buf);
        
        out:
        
        module_put(THIS_MODULE);
        return newfd;
    } // if(netmon_set)
    else 
    {
        module_put(THIS_MODULE);

        return orig_sys_accept(sockfd, addr, addrlen);
    }
}


/**
 * Hooking the system call SYS_MOUNT
 * 
 */
static asmlinkage long my_sys_mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data)
{

    if (!try_module_get(THIS_MODULE))
        return -1;

    if(mountmon_set){
    
        char *path_buf, *p_to_buf;
        int curr_pid;
        // history time  print
        struct rtc_time result;
        struct timeval time;
        unsigned long local_time;
        
        // The path to the executable that runs the Server
        path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
        if(unlikely(!path_buf))
        {
            printk(KERN_DEBUG "KMonitor_Error: kmalloc for path_buf failed\n");
            goto out;
        }
        p_to_buf = get_exe_path_parent(path_buf);
        if(!p_to_buf)
        {
            printk(KERN_DEBUG "KMonitor_Error: get_exe_path(path_buf) failed\n");
            kfree(path_buf);
            goto out;
        }
        
        curr_pid = task_tgid_vnr(current->parent);
        
        printk(KERN_DEBUG "%s (pid:%d) mounted %s to %s using %s file system\n",p_to_buf, curr_pid, dev_name, dir_name, type);
        
        do_gettimeofday(&time);
        local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
        rtc_time_to_tm(local_time, &result);

        snprintf(tmp_line, LINE_LENGTH,
                 "%d/%d/%d %.2d:%.2d:%.2d, %s (pid:%d) mounted %s to %s using %s file system\n",
                 result.tm_mday, (result.tm_mon+1), (result.tm_year+1900), (result.tm_hour), (result.tm_min), (result.tm_sec),
                 p_to_buf, curr_pid, dev_name, dir_name, type);

        mutex_lock(&history_mutex);
        addhistory(tmp_line);
        mutex_unlock(&history_mutex);
        
        kfree(path_buf);
        
    }// if(mountmon_set)
    
    out:
    module_put(THIS_MODULE);

    return orig_sys_mount(dev_name, dir_name, type, flags, data);
}


// Hook all sys_xxx with my_sys_xxx
static void exchange_table(void)
{
    //ENABLE_WRITE_PROTECTION
    write_cr0(orig_cr0 & ~CR0_WP);
    
    orig_sys_open = syscall_table[__NR_open];
    syscall_table[__NR_open] = my_sys_open;
    
    orig_sys_read = syscall_table[__NR_read];
    syscall_table[__NR_read] = my_sys_read;
    
    orig_sys_write = syscall_table[__NR_write];
    syscall_table[__NR_write] = my_sys_write;
    
    orig_sys_listen = syscall_table[__NR_listen];
    syscall_table[__NR_listen] = my_sys_listen;
    
    orig_sys_accept = syscall_table[__NR_accept];
    syscall_table[__NR_accept] = my_sys_accept;
    
    orig_sys_mount = syscall_table[__NR_mount];
    syscall_table[__NR_mount] = my_sys_mount;
    
//     DISABLE_WRITE_PROTECTION
    write_cr0(orig_cr0);
}

// Unhook all sys_xxx with my_sys_xxx
static void exchange_table_back(void)
{
//  ENABLE_WRITE_PROTECTION
    write_cr0(orig_cr0 & ~CR0_WP);
    syscall_table[__NR_open] = orig_sys_open;
    syscall_table[__NR_read] = orig_sys_read;
    syscall_table[__NR_write] = orig_sys_write;
    syscall_table[__NR_listen] = orig_sys_listen;
    syscall_table[__NR_accept] = orig_sys_accept;
    syscall_table[__NR_mount] = orig_sys_mount;
//  DISABLE_WRITE_PROTECTION
    write_cr0(orig_cr0);
}


// this function will be called when someone will try to read the proc file
static ssize_t procfile_read(struct file *file, char *buffer, size_t length, loff_t *offset)  
{
    int i, ret, head, tail;
    static int finished = 0;
    static int length_count = 0;


    if (!try_module_get(THIS_MODULE))
        return 0;


    if (finished) {
        memset(procfs_read_buf, 0, PROCFS_READ_BUFFER_SIZE);
        finished = 0;
        length_count = 0;
        module_put(THIS_MODULE);

        return 0;
    }
    
    finished = 1;
    
    mutex_lock(&history_mutex);
    length_count += snprintf(procfs_read_buf, PROCFS_READ_BUFFER_SIZE - length_count, "KMonitor - Last Events:\n\n");
    
    head = km_history.head;
    tail = km_history.tail;
    i = 1;
    do{
        if(km_history.total == 0)
            break;
        length_count += snprintf(procfs_read_buf + length_count, PROCFS_READ_BUFFER_SIZE - length_count, "(%d) %s\n\n", i, &km_history.history[head][0]);
        head = (head + 1) % MAX_HISTORY;
        i++;
    }while(head != tail);

    length_count += snprintf(procfs_read_buf + length_count, PROCFS_READ_BUFFER_SIZE - length_count, "KMonitor Current Configuration:\n\n");
    length_count += snprintf(procfs_read_buf + length_count, PROCFS_READ_BUFFER_SIZE - length_count, "File monitoring    - %s \n\n", (filemon_set  ? "Enable" : "Disable"));
    length_count += snprintf(procfs_read_buf + length_count, PROCFS_READ_BUFFER_SIZE - length_count, "Network Monitoring - %s \n\n", (netmon_set   ? "Enable" : "Disable"));
    length_count += snprintf(procfs_read_buf + length_count, PROCFS_READ_BUFFER_SIZE - length_count, "Mount Monitoring   - %s \n\n", (mountmon_set ? "Enable" : "Disable"));
    
    mutex_unlock(&history_mutex);
    
    copy_to_user(buffer, procfs_read_buf, length_count);

    ret = length_count;

    module_put(THIS_MODULE);

    return ret;
}

/**
 * This function is called when the /proc/KMonitor file is beeing written
 *
 */
static ssize_t procfile_write(struct file *file, const char __user *buffer, size_t count, loff_t *data)
{

       if (!try_module_get(THIS_MODULE))
        return 0;
 // Make sure that the size of the buffer from user 
    // is not larger from PROCFS_MAX_SIZE
    procfs_buffer_size = count;
    if (procfs_buffer_size > PROCFS_MAX_SIZE ) {
        procfs_buffer_size = PROCFS_MAX_SIZE;
    }
    
    // Copy data from user space (buffer) to the procfs_buffer
    if ( copy_from_user(procfs_buffer, buffer, procfs_buffer_size) ) {
        module_put(THIS_MODULE);

        return -EFAULT;
    }
    
    if (strncmp(procfs_buffer, "FileMon 0", 9 ) == 0)
        filemon_set = 0;
    else if (strncmp(procfs_buffer, "FileMon 1", 9 ) == 0)
        filemon_set = 1;
    else if (strncmp(procfs_buffer, "NetMon 0", 8) == 0)
        netmon_set = 0;
    else if (strncmp(procfs_buffer, "NetMon 1", 8 ) == 0)
        netmon_set = 1;
    else if (strncmp(procfs_buffer, "MountMon 0", 10 ) == 0)
        mountmon_set = 0;
    else if (strncmp(procfs_buffer, "MountMon 1", 10 )==0)
        mountmon_set = 1;
    else printk(KERN_DEBUG "KMonitor Error: Unknown operation %s\n", procfs_buffer);
    
    module_put(THIS_MODULE);

    return procfs_buffer_size;
}


/**
 * SYSCALL_INIT
 * 1. lookup for the syscall_table
 * 2. hooking the relevant system calls
 * 3. Create KMonitor file in /proc/
 * Initialize the mutex is in the header
 */
static int __init syscall_init(void)
{
    
    printk(KERN_DEBUG "KMonitor Moudule initializing...\n");
    // process table register
    orig_cr0 = read_cr0();
    km_history.head = 0;
    km_history.tail = 0;
    km_history.total = 0;
    
    // get the sys_call_table address
    syscall_table = (void **) find_sys_call_table();
    if (!syscall_table) {
        printk(KERN_DEBUG "ERROR: Cannot find the system call table address.\n"); 
        return -1;
    }
    
    printk(KERN_DEBUG "Found the sys_call_table at %16lx.\n", (unsigned long) syscall_table);
    
    // Hook all relevant system call   
    exchange_table();
    
    //-------------------------------------------------------------------------------
    // The code after this is for adding a file to /proc/ , With our write and read functions
    Our_Proc_File = proc_create(PROCFS_NAME, S_IFREG | S_IRUGO, NULL, &cmd_file_ops);
    if (Our_Proc_File == NULL) 
    {
        remove_proc_entry(PROCFS_NAME, NULL);
        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }
    
    /*
     * KUIDT_INIT is a macro defined in the file 'linux/uidgid.h'. KGIDT_INIT also appears here.
     */
    proc_set_user(Our_Proc_File, KUIDT_INIT(0), KGIDT_INIT(0));
    proc_set_size(Our_Proc_File, 37);
    
    printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);
    
    return 0;
}


static void __exit syscall_release(void)
{
    
    mutex_destroy(&history_mutex);        /// destroy the dynamically-allocated mutex
    printk(KERN_DEBUG "Releasing module KMonitor...\n");
    remove_proc_entry(PROCFS_NAME, NULL);
    orig_cr0 = read_cr0();

    exchange_table_back();                                                       // restore original sys call table state
    printk(KERN_INFO "/proc/%s removed\n", PROCFS_NAME);
}

module_init(syscall_init);
module_exit(syscall_release);
