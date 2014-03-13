/*
 * This file is part of libsmack.
 *
 * Copyright (C) 2011-2013 Intel Corporation
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef COMMON_H
#define COMMON_H

#define ACCESSES_D_PATH "/etc/smack/accesses.d"
#define CIPSO_D_PATH "/etc/smack/cipso.d"

int clear(void);
int apply_rules(const char *path, int clear);
int apply_cipso(const char *path);

#endif // COMMON_H
