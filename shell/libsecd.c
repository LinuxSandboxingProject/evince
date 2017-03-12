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

#include "libsecd.h"
#include <stdio.h>

//todo: set this flag in makefile
#define HAVE_LIBSECCOMP

#ifdef HAVE_LIBSECCOMP

#include <seccomp.h> /* libseccomp */
#include <sys/prctl.h> /* prctl */
#include <sys/socket.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>

#define ALLOW_RULE(call) { if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(call), 0) < 0) goto out; }

// init the filter
scmp_filter_ctx ctx;

int applyFilter(void) {

    // prevent child processes from getting more priv e.g. via setuid, capabilities, ...
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl SET_NO_NEW_PRIVS");
        exit(EXIT_FAILURE);
    }

    // prevent escape via ptrace
    if(prctl (PR_SET_DUMPABLE, 0, 0, 0, 0)){
        perror("prctl PR_SET_DUMPABLE");
        exit(EXIT_FAILURE);
    }


    // todo change to KILL
    ctx = seccomp_init(SCMP_ACT_TRAP);
    if (ctx == NULL)
        return 1;

    ALLOW_RULE (access);
    ALLOW_RULE (arch_prctl);
    ALLOW_RULE (brk);
    ALLOW_RULE (clone);
    ALLOW_RULE (close);
    ALLOW_RULE (connect);
    ALLOW_RULE (eventfd2);
    ALLOW_RULE (execve);
    ALLOW_RULE (exit);
    ALLOW_RULE (exit_group);
    ALLOW_RULE (fcntl);
    ALLOW_RULE (fstat);
    ALLOW_RULE (futex);
    ALLOW_RULE (getegid);
    ALLOW_RULE (geteuid);
    ALLOW_RULE (getrlimit);
    ALLOW_RULE (mmap);
    ALLOW_RULE (mprotect);
    ALLOW_RULE (munmap);
    ALLOW_RULE (open);
    ALLOW_RULE (poll);
    ALLOW_RULE (prctl);
    ALLOW_RULE (read);
    ALLOW_RULE (recvfrom);
    ALLOW_RULE (recvmsg);
    ALLOW_RULE (rt_sigaction);
    ALLOW_RULE (rt_sigprocmask);
    ALLOW_RULE (seccomp);
    ALLOW_RULE (sendmsg);
    ALLOW_RULE (sendto);
    ALLOW_RULE (set_robust_list);
    ALLOW_RULE (set_tid_address);
    ALLOW_RULE (socket);
    ALLOW_RULE (write);



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


    printf("applying filter... \n");
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

int applyFilter(void){

    printf("No seccomp support compiled-in\n");
    return 1;
}

#endif /* HAVE_LIBSECCOMP */
