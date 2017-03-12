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

#ifndef SECCOMP_H
#define SECCOMP_H

/* basic filter */
// this mode allows normal use
// only dangerous syscalls are blacklisted
int protectedMode(void);

/* secure read-only mode */
// whitelist minimal syscalls only
// this mode does not allow writing files
// or to open external links and applications
// network connections are prohibited as well
int protectedView(void);

#endif
