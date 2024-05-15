/* libnts - a minimalistic RFC8915 implementation supporting custom transport
 * Copyright (C) 2024: ABL GmbH
 *
 * This program is available under two distinct licenses:
 * You may either choose to
 *  a) adhere to the GNU General Public License version 2,
 *     as published by the Free Software Foundation, or
 *  b) obtain a commercial license from ABL GmbH,
 *     Albert-Büttner-Straße 11, 91207 Lauf an der Pegnitz, Germany.
 * */
/* This header shall #include all declarations and typdefs
 * required for interfacing with libnts.
 * */
#ifndef NTS_H
#define NTS_H

/* Take care of environments with libc lacking basic functionality
 * */
#ifdef LIBNTS_DECLARE_BASICS_MISSING_IN_OPTEEE
  #include "nts/required_basics.h"
#endif

/* typedef ntserror
 * declare ntsErrorAsString
 * */
#include "nts/nts_error.h"

/* Declare all functions for indicating and querying the remotes
 * */
#include "nts/remote.h"

/* Declare all cookie related functions
 * */
#include "nts/cookie.h"

/* Declare all hash related functions
 * */
#include "nts/hashes.h"

/* Declare all functions related to exporting and importing keys
 * */
#include "nts/keys.h"

/* Declare requestTime function
 * */
#include "nts/ntsv4.h"

/* Declare all io functions that a program has to provide to libnts.
 * */
#include "nts/io.h"

/* Declare utility functions that libnts implements
 * */
#include "nts/util.h"

#endif /* NTS_H */
