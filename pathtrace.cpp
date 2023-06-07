#include "pin.H"
#include<string>
#include<iostream>
#include<fstream>
#include<map>

using std::cout;
using std::endl;
using std::hex;
using std::dec;
using std::string;
using std::map;

ADDRINT low_addr = 0;
ADDRINT high_addr = 0;
ADDRINT load_offset = 0;

map<ADDRINT, string> map_dis;
map<string, int> syscall_hitcount;

string syscalls_64[]={"read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module", "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll", "unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev", "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2", "seccomp", "getrandom", "memfd_create", "kexec_file_load", "bpf", "execveat", "userfaultfd", "membarrier", "mlock2", "copy_file_range", "preadv2", "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free", "statx"};
string syscalls_32[]={"restart_syscall", "exit", "fork", "read", "write", "open", "close", "waitpid", "creat", "link", "unlink", "execve", "chdir", "time", "mknod", "chmod", "lchown", "break", "oldstat", "lseek", "getpid", "mount", "umount", "setuid", "getuid", "stime", "ptrace", "alarm", "oldfstat", "pause", "utime", "stty", "gtty", "access", "nice", "ftime", "sync", "kill", "rename", "mkdir", "rmdir", "dup", "pipe", "times", "prof", "brk", "setgid", "getgid", "signal", "geteuid", "getegid", "acct", "umount2", "lock", "ioctl", "fcntl", "mpx", "setpgid", "ulimit", "oldolduname", "umask", "chroot", "ustat", "dup2", "getppid", "getpgrp", "setsid", "sigaction", "sgetmask", "ssetmask", "setreuid", "setregid", "sigsuspend", "sigpending", "sethostname", "setrlimit", "getrlimit", "getrusage", "gettimeofday", "settimeofday", "getgroups", "setgroups", "select", "symlink", "oldlstat", "readlink", "uselib", "swapon", "reboot", "readdir", "mmap", "munmap", "truncate", "ftruncate", "fchmod", "fchown", "getpriority", "setpriority", "profil", "statfs", "fstatfs", "ioperm", "socketcall", "syslog", "setitimer", "getitimer", "stat", "lstat", "fstat", "olduname", "iopl", "vhangup", "idle", "vm86old", "wait4", "swapoff", "sysinfo", "ipc", "fsync", "sigreturn", "clone", "setdomainname", "uname", "modify_ldt", "adjtimex", "mprotect", "sigprocmask", "create_module", "init_module", "delete_module", "get_kernel_syms", "quotactl", "getpgid", "fchdir", "bdflush", "sysfs", "personality", "afs_syscall", "setfsuid", "setfsgid", "_llseek", "getdents", "_newselect", "flock", "msync", "readv", "writev", "getsid", "fdatasync", "_sysctl", "mlock", "munlock", "mlockall", "munlockall", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_yield", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "nanosleep", "mremap", "setresuid", "getresuid", "vm86", "query_module", "poll", "nfsservctl", "setresgid", "getresgid", "prctl", "rt_sigreturn", "rt_sigaction", "rt_sigprocmask", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "pread64", "pwrite64", "chown", "getcwd", "capget", "capset", "sigaltstack", "sendfile", "getpmsg", "putpmsg", "vfork", "ugetrlimit", "mmap2", "truncate64", "ftruncate64", "stat64", "lstat64", "fstat64", "lchown32", "getuid32", "getgid32", "geteuid32", "getegid32", "setreuid32", "setregid32", "getgroups32", "setgroups32", "fchown32", "setresuid32", "getresuid32", "setresgid32", "getresgid32", "chown32", "setuid32", "setgid32", "setfsuid32", "setfsgid32", "pivot_root", "mincore", "madvise", "getdents64", "fcntl64", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "sendfile64", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "get_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "fadvise64", "exit_group", "lookup_dcookie", "epoll_create", "epoll_ctl", "epoll_wait", "remap_file_pages", "set_tid_address", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "statfs64", "fstatfs64", "tgkill", "utimes", "fadvise64_64", "vserver", "mbind", "get_mempolicy", "set_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "fstatat64", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll", "unshare", "set_robust_list", "get_robust_list", "splice", "sync_file_range", "tee", "vmsplice", "move_pages", "getcpu", "epoll_pwait", "utimensat", "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime", "signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs", "sendmmsg", "setns", "process_vm_readv", "process_vm_writev", "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2", "seccomp", "getrandom", "memfd_create", "bpf", "execveat", "socket", "socketpair", "bind", "connect", "listen", "accept4", "getsockopt", "setsockopt", "getsockname", "getpeername", "sendto", "sendmsg", "recvfrom", "recvmsg", "shutdown", "userfaultfd", "membarrier", "mlock2", "copy_file_range", "preadv2", "pwritev2"};

int syscalls=0;
int calls=0;
int brs=0;

/*
syscall  id  sys_str   
jxx  cur_loc  tar_loc  disassemble
call cur_loc  tar_loc  disassemble
*/

VOID before_call(ADDRINT addr_inst, ADDRINT target){
    ADDRINT offset_inst = addr_inst - load_offset;
    ADDRINT offset_target = 0;
    if (target < low_addr || target > high_addr){
        offset_target = target;
    }
    else{
        offset_target = target - load_offset;
    }
    string rtn_name = RTN_FindNameByAddress(target);
    cout << "call\t cur_loc: 0x" << hex << offset_inst << "\t " << "target_loc: 0x" << hex << offset_target << "\t " << map_dis[addr_inst] <<"\t "<<rtn_name<< endl; 
}

VOID before_jmp(ADDRINT addr_inst, ADDRINT target){
    ADDRINT offset_inst = addr_inst - load_offset;
    ADDRINT offset_target = 0;
    if (target < low_addr || target > high_addr){
        offset_target = target;
    }
    else{
        offset_target = target - load_offset;
    }

    cout << "br\t cur_loc: 0x" << hex << offset_inst << "\t " << "target_loc: 0x" << hex << offset_target << "\t " << map_dis[addr_inst] << endl; 
}

/*VOID before_ret(ADDRINT addr_inst, ADDRINT target){
    ADDRINT offset_inst = addr_inst - load_offset;
    ADDRINT offset_target = 0;
    if (target < low_addr || target > high_addr){
        offset_target = target;
    }
    else{
        offset_target = target - load_offset;
    }
    string rtn_name = RTN_FindNameByAddress(target);
    cout<< "0x" << hex << offset_inst << "\t ret, target is 0x" << hex << offset_target << "\t; Return "<< rtn_name << endl;
}*/

//VOID after_call(ADDRINT addr_inst){
//
//}

VOID Trace(TRACE trace, VOID *v){

    for(BBL bbl=TRACE_BblHead(trace); BBL_Valid(bbl); bbl=BBL_Next(bbl)){
        INS tail = BBL_InsTail(bbl);

        ADDRINT addr = INS_Address(tail);
        if ( addr < low_addr || addr > high_addr) continue;

        if(INS_IsCall(tail)){

            string dis = INS_Disassemble(tail);
            ADDRINT addr = INS_Address(tail);
            map_dis[addr] = dis;
            //cout<< "0x" << hex << INS_Address(tail) << "\t" << INS_Disassemble(tail) << endl;
            //if(INS_IsDirectCall(tail)){
            //    const ADDRINT target = INS_DirectControlFlowTargetAddress(tail);
            //    cout << "Call instruction: 0x" << INS_Address(tail) << "\t" << INS_Disassemble(tail) << endl;
            //    cout << "Call target is 0x" << hex << target << endl;
            //}
            //else{
            //    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(indirect_call),
            //                    IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,
            //                    IARG_END);
            //}
            INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(before_call), 
                            IARG_INST_PTR, 
                            IARG_BRANCH_TARGET_ADDR, IARG_END);
            calls++;
            continue;
        }
        /*if(INS_IsRet(tail)){
            INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(before_ret),
                            IARG_INST_PTR,
                            IARG_BRANCH_TARGET_ADDR, IARG_END);
            continue;
        }*/
        if(INS_IsBranch(tail)){

            string dis = INS_Disassemble(tail);
            ADDRINT addr = INS_Address(tail);
            map_dis[addr] = dis;
            INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(before_jmp), 
                            IARG_INST_PTR, 
                            IARG_BRANCH_TARGET_ADDR, IARG_END);
            brs++;
            continue;
        }
    }
}

VOID Image(IMG img, VOID *v){

    if(!IMG_IsMainExecutable(img)) return; 
    low_addr = IMG_LowAddress(img);
    high_addr = IMG_HighAddress(img);
    load_offset = IMG_LoadOffset(img);
    cout << IMG_Name(img) << endl;
    cout << "Memory range: 0x" << hex << low_addr << " -- 0x" << hex << high_addr << endl;
	cout << "Load addr: 0x" << hex <<load_offset << endl;
}

VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v){
    ADDRINT syscall_id = PIN_GetSyscallNumber(ctx, std);
    string syscall_str = syscalls_64[syscall_id];
    syscalls++;
    syscall_hitcount[syscall_str]++;
    cout << "syscall\t id: "<< dec << syscall_id <<"\t "<<"sys_"<< syscall_str <<endl;
}

VOID Fini(INT32 code, VOID* v){
    cout<<"number of syscall: "<<syscalls<<endl;
    cout<<"number of call: "<<calls<<endl;
    cout<<"number of jxx: "<<brs<<endl;
    for(auto it:syscall_hitcount){
        cout<<it.first<<"\t "<<it.second<<endl;
    }
}

int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return 1;

    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddSyscallEntryFunction(Syscall_entry, 0);
    IMG_AddInstrumentFunction(Image, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram(); 
    return 0;
}
