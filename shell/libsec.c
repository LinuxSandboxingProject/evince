/*
 *  Copyright (C) 2017 valoq <valoq@mailbox.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include "libsec.h"
#include <stdio.h>

#define HAVE_LIBSECCOMP
#ifdef HAVE_LIBSECCOMP

#include <seccomp.h> /* libseccomp */
#include <sys/prctl.h> /* prctl */
#include <sys/socket.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>

#define DENY_RULE(call) { if (seccomp_rule_add (ctx, SCMP_ACT_KILL, SCMP_SYS(call), 0) < 0) goto out; }
#define ALLOW_RULE(call) { if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(call), 0) < 0) goto out; }

scmp_filter_ctx ctx;

int protectedMode(void){

    // prevent child processes from getting more priv e.g. via setuid, capabilities, ...
    //prctl(PR_SET_NO_NEW_PRIVS, 1);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl SET_NO_NEW_PRIVS");
        exit(EXIT_FAILURE);
    }


    // prevent escape via ptrace
    //prctl(PR_SET_DUMPABLE, 0);

    if(prctl (PR_SET_DUMPABLE, 0, 0, 0, 0)){
        perror("prctl PR_SET_DUMPABLE");
        exit(EXIT_FAILURE);
    }


    // initialize the filter
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL)
        return 1;

    DENY_RULE (_sysctl);
    DENY_RULE (acct);
    DENY_RULE (add_key);
    DENY_RULE (adjtimex);
    DENY_RULE (chroot);
    DENY_RULE (clock_adjtime);
    DENY_RULE (create_module);
    DENY_RULE (delete_module);
    DENY_RULE (fanotify_init);
    DENY_RULE (finit_module);
    DENY_RULE (get_kernel_syms);
    DENY_RULE (get_mempolicy);
    DENY_RULE (init_module);
    DENY_RULE (io_cancel);
    DENY_RULE (io_destroy);
    DENY_RULE (io_getevents);
    DENY_RULE (io_setup);
    DENY_RULE (io_submit);
    DENY_RULE (ioperm);
    DENY_RULE (iopl);
    DENY_RULE (ioprio_set);
    DENY_RULE (kcmp);
    DENY_RULE (kexec_file_load);
    DENY_RULE (kexec_load);
    DENY_RULE (keyctl);
    DENY_RULE (lookup_dcookie);
    DENY_RULE (mbind);
    DENY_RULE (nfsservctl);
    DENY_RULE (migrate_pages);
    DENY_RULE (modify_ldt);
    DENY_RULE (mount);
    DENY_RULE (move_pages);
    DENY_RULE (name_to_handle_at);
    DENY_RULE (open_by_handle_at);
    DENY_RULE (perf_event_open);
    DENY_RULE (pivot_root);
    DENY_RULE (process_vm_readv);
    DENY_RULE (process_vm_writev);
    DENY_RULE (ptrace);
    DENY_RULE (reboot);
    DENY_RULE (remap_file_pages);
    DENY_RULE (request_key);
    DENY_RULE (set_mempolicy);
    DENY_RULE (swapoff);
    DENY_RULE (swapon);
    DENY_RULE (sysfs);
    DENY_RULE (syslog);
    DENY_RULE (tuxcall);
    DENY_RULE (umount2);
    DENY_RULE (uselib);
    DENY_RULE (vmsplice);


    //applying filter...
    if (seccomp_load (ctx) >= 0){
	// free ctx after the filter has been loaded into the kernel
	seccomp_release(ctx);
        return 0;
    }

    
  out:
    //something went wrong
    seccomp_release(ctx);
    return 1;
}


int protectedView(void){

    // prevent child processes from getting more priv e.g. via setuid, capabilities, ...
    //prctl(PR_SET_NO_NEW_PRIVS, 1);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl SET_NO_NEW_PRIVS");
        exit(EXIT_FAILURE);
    }


    // prevent escape via ptrace
    //prctl(PR_SET_DUMPABLE, 0);

    if(prctl (PR_SET_DUMPABLE, 0, 0, 0, 0)){
        perror("prctl PR_SET_DUMPABLE");
        exit(EXIT_FAILURE);
    }

    // initialize the filter
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL)
        return 1;


    ALLOW_RULE (access);
    ALLOW_RULE (arch_prctl);
    ALLOW_RULE (brk);
    ALLOW_RULE (chdir);
    ALLOW_RULE (chmod);
    ALLOW_RULE (clock_getres);
    ALLOW_RULE (clone);
    ALLOW_RULE (close);
    ALLOW_RULE (connect);
      ALLOW_RULE (dup2);
    ALLOW_RULE (eventfd2);
    ALLOW_RULE (exit);
    ALLOW_RULE (exit_group);
    ALLOW_RULE (fadvise64);
    ALLOW_RULE (fallocate);
    ALLOW_RULE (fcntl);
    ALLOW_RULE (fstat);
    ALLOW_RULE (fstatfs);
    ALLOW_RULE (fsync);
    ALLOW_RULE (futex);
    ALLOW_RULE (getdents);
    ALLOW_RULE (getegid);
    ALLOW_RULE (geteuid);
      ALLOW_RULE (getgid);
      ALLOW_RULE (getuid);
    ALLOW_RULE (getpid);
      ALLOW_RULE (getppid);
    ALLOW_RULE (getpeername);
      ALLOW_RULE (getpgrp);
      ALLOW_RULE (getrandom);
    ALLOW_RULE (getresgid);
    ALLOW_RULE (getresuid);
    ALLOW_RULE (getrlimit);
    ALLOW_RULE (getsockname);
    ALLOW_RULE (getsockopt);  /* needed for access to x11 socket in network namespace (without abstract sockets) */
    ALLOW_RULE (getuid);
    ALLOW_RULE (inotify_add_watch);
    ALLOW_RULE (inotify_init1);
    ALLOW_RULE (inotify_rm_watch);
    ALLOW_RULE (ioctl);
    ALLOW_RULE (lseek);
    ALLOW_RULE (lstat);
    ALLOW_RULE (madvise);
    ALLOW_RULE (mmap);
    ALLOW_RULE (mprotect);
    ALLOW_RULE (munmap);
    //ALLOW_RULE (open);
      ALLOW_RULE (pipe);
    ALLOW_RULE (poll);
    ALLOW_RULE (prctl);
    ALLOW_RULE (pread64);
    ALLOW_RULE (prlimit64);
    ALLOW_RULE (pwrite64);
    ALLOW_RULE (read);
    ALLOW_RULE (recvfrom);
    ALLOW_RULE (recvmsg);
    ALLOW_RULE (rename);
    ALLOW_RULE (restart_syscall);
    ALLOW_RULE (rt_sigaction);
    ALLOW_RULE (rt_sigprocmask);
    ALLOW_RULE (sendmsg);
    ALLOW_RULE (sendto);
    ALLOW_RULE (set_robust_list);
    ALLOW_RULE (set_tid_address);
    ALLOW_RULE (shmat);
    ALLOW_RULE (shmctl);
    ALLOW_RULE (shmdt);
    ALLOW_RULE (shmget);
    ALLOW_RULE (shutdown);
    //ALLOW_RULE (socket);
    ALLOW_RULE (stat);
    ALLOW_RULE (statfs);
      ALLOW_RULE (sysinfo);
    ALLOW_RULE (uname);
      ALLOW_RULE (wait4);
    ALLOW_RULE (write);
    ALLOW_RULE (writev);

    //link
    //unlink

    // needed for save copy, (writing new files) -- to be reviewed

    ALLOW_RULE (flistxattr);
    ALLOW_RULE (getcwd);
    ALLOW_RULE (lchown);
    ALLOW_RULE (listxattr);
    ALLOW_RULE (mkdir);
    ALLOW_RULE (pipe2);
    ALLOW_RULE (readlink);
    ALLOW_RULE (rmdir);
    ALLOW_RULE (splice);

    ALLOW_RULE (unlink);
    ALLOW_RULE (utimes);


    // prevent network access and open files for writing

    /* special restrictions for socket, only allow AF_UNIX/AF_LOCAL */
    if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1,
			  SCMP_CMP(0, SCMP_CMP_EQ, AF_UNIX)) < 0)
	goto out;

    if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1,
			  SCMP_CMP(0, SCMP_CMP_EQ, AF_LOCAL)) < 0)
	goto out;


    /* special restrictions for open, allow only reading files */
    if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
			  SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY | O_RDWR, 0)) < 0)
	goto out;

    if (seccomp_rule_add (ctx, SCMP_ACT_ERRNO (EACCES), SCMP_SYS(open), 1,
			  SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY)) < 0)
	goto out;

    if (seccomp_rule_add (ctx, SCMP_ACT_ERRNO (EACCES), SCMP_SYS(open), 1,
			  SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR)) < 0)
	goto out;

	
    /* restrict fcntl calls */
    // this syscall sets the file descriptor to read write
    // if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 1,
    //                             SCMP_CMP(0, SCMP_CMP_EQ, 3)) < 0 )
    //     goto out;
    // fcntl(3, F_GETFL)                       = 0x2 (flags O_RDWR)
    // fcntl(3, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
    // fcntl(3, F_SETFD, FD_CLOEXEC)           = 0


    //applying filter...
    if (seccomp_load (ctx) >= 0){
	// free ctx after the filter has been loaded into the kernel
	seccomp_release(ctx);
        return 0;
    }

	
 out:
    //something went wrong
    seccomp_release(ctx);
    return 1;
}

#else /* HAVE_LIBSECCOMP */


int protectedMode(void){

    perror("No seccomp support compiled-in\n");
    return 1;
}

int protectedView(void){

    perror("No seccomp support compiled-in\n");
    return 1;
}

#endif /* HAVE_LIBSECCOMP */
