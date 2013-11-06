/* none.c
 * Basic/example dispatcher module
 *
 * $Id:  $
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
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "proto.h"
#include "log.h"
#include "pei.h"
#include "gearth.h"

#define DNS_TMP_DIR     "dns"
#define DNS_EN          0

static unsigned long geo_id; /* geo session number, in this case we have only one session */

/* dns */
static int dns_id;
static int pei_dns_host_id;
static int pei_dns_ip_id;
static int pei_dns_cname_id;
static int pei_dns_pkt_id;
static FILE *dns_fp;

static int DispDns(pei *ppei)
{
    pei_component *cmpn;
    char *ip_one, *host, *cname, *id;
    
    ip_one = NULL;
    host = NULL;
    cname = NULL;
    id = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_dns_host_id) {
            host = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_dns_ip_id && ip_one == NULL) {
            ip_one = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_dns_cname_id && cname == NULL) {
            cname = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_dns_pkt_id) {
            id = cmpn->strbuf;
        }
        cmpn = cmpn->next;
    }
    if (ip_one != NULL || cname != NULL) {
        if (cname == NULL)
            cname = "";
        if (ip_one == NULL)
            ip_one = "";
        if (id == NULL)
            id = "";
        if (dns_fp != NULL) {
            fprintf(dns_fp, "%s, %lu, %s, %s, %s\n", id, ppei->time_cap, host, cname, ip_one);
        }
    }
    
    return 0;
}


int DispInit(const char *cfg_file)
{
    char kml_file[256];
    char dns_dir_file[256];

    LogPrintf(LV_DEBUG, "None Dispatcher");

#if DNS_EN
    geo_id = 0;
    sprintf(kml_file, "%s/geomap_%lu.kml", ProtTmpDir(), (time(NULL)/100)*100);
    GearthNew(geo_id, kml_file, NULL, NULL);

    dns_id = ProtId("dns");
    if (dns_id != -1) {
        pei_dns_host_id =  ProtPeiComptId(dns_id, "host");
        pei_dns_ip_id =  ProtPeiComptId(dns_id, "ip");
        pei_dns_cname_id =  ProtPeiComptId(dns_id, "cname");
        pei_dns_pkt_id = ProtPeiComptId(dns_id, "id");
    }
    /* dns tmp directory */
    sprintf(dns_dir_file, "%s/%s", ProtTmpDir(), DNS_TMP_DIR);
    mkdir(dns_dir_file, 0x01FF);
    sprintf(dns_dir_file, "%s/%s/dns_%lu.txt", ProtTmpDir(), DNS_TMP_DIR, time(NULL));
    dns_fp = fopen(dns_dir_file, "w");
    if (dns_fp != NULL) {
        fprintf(dns_fp, "# ID, timestamp [s], host, cname, ip (first IP)\n\n");
    }
#endif

    return 0;
}


int DispEnd(void)
{
    GearthClose(geo_id);
    if (dns_fp != NULL)
        fclose(dns_fp);
    
    return 0;
}


int DispInsPei(pei *ppei)
{    
    if (ppei != NULL) {
#if DNS_EN
        if (ppei->prot_id == dns_id) {
            DispDns(ppei);
        }
        else
#endif
        {
            PeiPrint(ppei);
            ProtStackFrmDisp(ppei->stack, TRUE);
        }
        //GearthPei(geo_id, ppei);
    }
    
    return 0;
}

