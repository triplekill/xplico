/* report.c
 * report in a socket connection the Xplico status/statistics
 *
 * $Id: report.c,v 1.6 2007/11/07 14:26:29 costa Exp $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <stdio.h>
#include <time.h>

#include "proto.h"
#include "report.h"
#include "fthread.h"
#include "capture.h"
#include "dispatch.h"
#include "dnsdb.h"
#include "grp_flows.h"

extern int GrpStatus(void);

int ReportInit(void)
{
    return 0;
}


int ReportSplash(void)
{
    unsigned int dns_ip, dns_name;
    unsigned long dns_size;
    time_t t;

    ProtStatus();
    DispatchStatus();
    printf("Fthread: %lu/%lu\n", FthreadRunning(), FthreadTblDim());
    printf("Flows: %lu\n", FlowNumber());
    GrpStatus();
    DnsDbStatus(&dns_ip, &dns_name, &dns_size);
    printf("Dns DB: ip number: %i, name number: %i, total size: %lu\n", dns_ip, dns_name, dns_size);
    t = FlowGetGblTime();
    printf("Data source: %s\n", CapSource());
    printf("Cap. time: %s\n", ctime(&t));

    return 0;
}

