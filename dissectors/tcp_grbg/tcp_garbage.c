/* tcp_garbage.c
 * Dissector to group together packet of tcp flow that haven't a specific dissector
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2012 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
//#include <linux/tcp.h>
#include <dirent.h>
#include <ctype.h>

#include "proto.h"
#include "dmemory.h"
#include "config_file.h"
#include "etypes.h"
#include "flow.h"
#include "log.h"
#include "dnsdb.h"
#include "tcp_garbage.h"
#include "pei.h"

/* nDPI library */
#include "libndpi/ndpi_api.h"
#include "libndpi/ndpi_main.h"
#include "libndpi/ndpi_structs.h"


#define GRB_FILE           0           /* to put (or not) data in to a pcap file */
#define TCP_GRB_TMP_DIR    "tcp_grb"
#define NDPI_TICK_RES      1000        /* Hz */
#define GRB_TXT_ENABLE     1

static int ppp_id;
static int eth_id;
static int ip_id;
static int ipv6_id;
static int tcp_id;
static int ip_src_id;
static int ip_dst_id;
static int ip_offset_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int ipv6_offset_id;
static int port_src_id;
static int port_dst_id;
static int lost_id;
static int tcp_grb_id;
static volatile int serial = 0;

/* pei id */
static int pei_l7protocol_id;
static int pei_txt_id;
static int pei_size_id;

static volatile unsigned int incr;
/* ndpi */
static struct ndpi_detection_module_struct *ndpi = NULL;
static pthread_mutex_t ndpi_mux;  /* mutex to access the ndpi handler */
static unsigned int ndpi_flow_struct_size;
static unsigned int ndpi_proto_size;
/* static char *ndpi_prot_str[] = { NDPI_PROTOCOL_LONG_STRING }; */
static long limit_pkts;


static void *nDPImalloc(unsigned long size)
{
    return malloc(size);
}


static void nDPIfree(void *freeable)
{
    free(freeable);
}


static void nDPIPrintf(u_int32_t protocol, void *id_struct, ndpi_log_level_t log_level, const char *format, ...)
{
    return;
}


static unsigned int nDPIPacket(packet *pkt, struct ndpi_flow_struct *l7flow, struct ndpi_id_struct *l7src, struct ndpi_id_struct *l7dst, bool ipv4)
{
    void *data;
    size_t offset, size;
    ftval voffset;
    const pstack_f *ip;
    unsigned long when;
    unsigned int l7prot_id;

    if (ipv4) {
        ip = ProtStackSearchProt(pkt->stk, ip_id);
        ProtGetAttr(ip, ip_offset_id, &voffset);
        offset = voffset.uint32;
        data = pkt->raw + offset;
        size = pkt->raw_len - offset;
    }
    else {
        ip = ProtStackSearchProt(pkt->stk, ipv6_id);
        ProtGetAttr(ip, ipv6_offset_id, &voffset);
        offset = voffset.uint32;
        data = pkt->raw + offset;
        size = pkt->raw_len - offset;
    }
    when = pkt->cap_sec;
    when = when * NDPI_TICK_RES;
    when += pkt->cap_usec/1000;  /* (1000000 / NDPI_TICK_RES) */;
    pthread_mutex_lock(&ndpi_mux);
    l7prot_id = ndpi_detection_process_packet(ndpi, l7flow, data, size, when, l7src, l7dst);
    pthread_mutex_unlock(&ndpi_mux);

    return l7prot_id;
}


static bool TcpGrbCheck(int flow_id)
{
    unsigned long pkt_num;

    pkt_num = FlowPktNum(flow_id);
    if (pkt_num > limit_pkts || (pkt_num > 0 && FlowIsClose(flow_id) == TRUE)) {
        return TRUE;
    }

    return FALSE;
}


static bool TcpGrbMajorityText(unsigned char *dat, unsigned int size)
{
    unsigned int perc, i, j;

    if (size == 0)
        return FALSE;
    
    perc = (size * TCP_GRB_PERCENTAGE)/100;
    
    j = 0;
    for (i=0; i!=size && j!=perc; i++) {
        if (0x1F<dat[i] && dat[i]<0x7F)
            j++;
    }
    if (j == perc)
        return TRUE;
    
    return FALSE;
}


static void TcpGrbText(FILE *fp, unsigned char *dat, unsigned int size)
{
    unsigned int i, j;
    
    j = 0;
    for (i=0; i!=size; i++) {
        if (dat[i]<0x7F)
            dat[j++] = dat[i];
    }
    fwrite(dat, 1, j, fp);
}


static void GrbPei(pei *ppei, const char *prot_name, size_t size, char *txt_file, time_t *cap_sec, time_t *end_cap)
{
    char val[TCP_GRB_FILENAME_PATH_SIZE];
    pei_component *cmpn;
    
    /* pei components */
    PeiNewComponent(&cmpn, pei_l7protocol_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, prot_name);
    PeiAddComponent(ppei, cmpn);
    
    if (txt_file != NULL) {
        PeiNewComponent(&cmpn, pei_txt_id);
        PeiCompCapTime(cmpn, *cap_sec);
        PeiCompCapEndTime(cmpn, *end_cap);
        PeiCompAddFile(cmpn, "Text", txt_file, 0);
        PeiAddComponent(ppei, cmpn);
    }

    sprintf(val, "%ul", size);
    PeiNewComponent(&cmpn, pei_size_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, val);
    PeiAddComponent(ppei, cmpn);
}


static bool TcpGrbClientPkt(tgrb_priv *priv, packet *pkt)
{
    bool ret;
    ftval port, ip;
    enum ftype type;
    
    ret = FALSE;
    if (priv->port_diff == TRUE) {
        ProtGetAttr(pkt->stk, port_src_id, &port);
        if (port.uint16 == priv->port_s)
            ret = TRUE;
    }
    else {
        if (priv->ipv6 == TRUE) {
            ProtGetAttr(ProtGetNxtFrame(pkt->stk), ipv6_src_id, &ip);
            type = FT_IPv6;
        }
        else {
            ProtGetAttr(ProtGetNxtFrame(pkt->stk), ip_src_id, &ip);
            type = FT_IPv4;
        }
        if (FTCmp(&priv->ip_s, &ip, type, FT_OP_EQ, NULL) == 0)
            ret = TRUE;
    }
    
    return ret;
}


packet *TcpGrbDissector(int flow_id)
{
    packet *pkt;
    tgrb_priv *priv;
    const pstack_f *tcp, *ip;
    ftval port_src, port_dst, lost;
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    bool ipv4;
    int count;
    int threshold;
    bool txt_data;
    FILE *txt_fp;
    char txt_file[TCP_GRB_FILENAME_PATH_SIZE];
    unsigned char *thrs;
    pei *ppei;
    time_t cap_sec, end_cap;
#if GRB_FILE
    int fd_pcap;
    char filename[256];
    int prot;
    struct pcap_file_header fh;
    struct pcap_pkthdr pckt_header;
#endif
    size_t flow_size;
    bool first_lost;
    const char *l7prot_type;
    struct ndpi_flow_struct *l7flow;
    struct ndpi_id_struct *l7src, *l7dst;
    unsigned int l7prot_id;
    unsigned char stage;
    
    LogPrintf(LV_DEBUG, "TCP garbage id: %d", flow_id);

    /* ndpi init */ 
    l7flow = xcalloc(1, ndpi_flow_struct_size);
    if (l7flow == NULL) {
        LogPrintf(LV_ERROR, "Out of memory");
        l7src = NULL;
        l7dst = NULL;
    }
    else {
        l7src = xcalloc(1, ndpi_proto_size);
        if (l7src != NULL) {
            l7dst = xcalloc(1, ndpi_proto_size);
            if (l7dst == NULL) {
                xfree(l7src);
                xfree(l7flow);
                l7src = NULL;
                l7flow = NULL;
            }
        }
        else {
            xfree(l7flow);
            l7flow = NULL;
            l7dst = NULL;
        }
    }

    /* init */
    priv = DMemMalloc(sizeof(tgrb_priv));
    memset(priv, 0, sizeof(tgrb_priv));
    tcp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(tcp);
    ProtGetAttr(tcp, port_src_id, &port_src);
    ProtGetAttr(tcp, port_dst_id, &port_dst);
    priv->port_s = port_src.uint16;
    priv->port_d = port_dst.uint16;
    priv->stack = tcp;
    if (priv->port_s != port_dst.uint16)
        priv->port_diff = TRUE;
    priv->ipv6 = TRUE;
    ipv4 = FALSE;
    first_lost = FALSE;
    stage = 0;
    if (ProtFrameProtocol(ip) == ip_id) {
        ipv4 = TRUE;
        priv->ipv6 = FALSE;
    }
    if (ipv4) {
        ProtGetAttr(ip, ip_src_id, &priv->ip_s);
        ProtGetAttr(ip, ip_dst_id, &priv->ip_d);
        ip_addr.s_addr = priv->ip_s.uint32;
        inet_ntop(AF_INET, &ip_addr, ips_str, INET6_ADDRSTRLEN);
        ip_addr.s_addr = priv->ip_d.uint32;
        inet_ntop(AF_INET, &ip_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    else {
        ProtGetAttr(ip, ipv6_src_id, &priv->ip_s);
        ProtGetAttr(ip, ipv6_dst_id, &priv->ip_d);
        memcpy(ipv6_addr.s6_addr, priv->ip_s.ipv6, sizeof(priv->ip_s.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ips_str, INET6_ADDRSTRLEN);
        memcpy(ipv6_addr.s6_addr, priv->ip_d.ipv6, sizeof(priv->ip_d.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ipd_str, INET6_ADDRSTRLEN);    
    }
    LogPrintf(LV_DEBUG, "\tSRC: %s:%d", ips_str, port_src.uint16);
    LogPrintf(LV_DEBUG, "\tDST: %s:%d", ipd_str, port_dst.uint16);
    
    /* file pcap */
#if GRB_FILE
    sprintf(filename, "%s/tcp_%d_grb_%s_%s.pcap", ProtTmpDir(), serial, ips_str, ipd_str);
    serial++;
    fd_pcap = open(filename, O_WRONLY | O_CREAT, 0x01B6);
    memset(&fh, 0, sizeof(struct pcap_file_header));
    fh.magic = 0xA1B2C3D4;
    fh.version_major = PCAP_VERSION_MAJOR;
    fh.version_minor = PCAP_VERSION_MINOR;
    fh.snaplen = 65535;
    if (ProtGetNxtFrame(ip) != NULL) {
        prot = ProtFrameProtocol(ProtGetNxtFrame(ip));
        if (prot == eth_id)
            fh.linktype = DLT_EN10MB;
        else if (prot == ppp_id)
            fh.linktype = DLT_PPP;
        else
            fh.linktype = DLT_RAW;
    }
    if (fd_pcap != -1)
        write(fd_pcap, (char *)&fh, sizeof(struct pcap_file_header));
#endif
    
    l7prot_type = NULL;
    flow_size = 0;
    count = 0;
    ppei = NULL;
    txt_data = FALSE;
    txt_fp = NULL;
    threshold = 0;
#if GRB_TXT_ENABLE
    thrs = xmalloc(TCP_GRB_THRESHOLD+1);
#else
    thrs = NULL;
#endif
    do {
        pkt = FlowGetPkt(flow_id);
        if (pkt != NULL) {
            ProtGetAttr(pkt->stk, lost_id, &lost);
            if (lost.uint8 == FALSE) {
                /* create pei */
                PeiNew(&ppei, tcp_grb_id);
                PeiCapTime(ppei, pkt->cap_sec);
                PeiMarker(ppei, pkt->serial);
                PeiStackFlow(ppei, tcp);
                cap_sec = pkt->cap_sec;
                end_cap = pkt->cap_sec;
                break;
            }
            else {
                first_lost = TRUE;
            }
        }
    } while (pkt != NULL);
    while (pkt != NULL) {
        flow_size += pkt->len;
        //ProtStackFrmDisp(pkt->stk, TRUE);
        ProtGetAttr(pkt->stk, lost_id, &lost);
        if (lost.uint8 == FALSE) {
            count++;
            end_cap = pkt->cap_sec;
            /* protocol type -ndpi- */
            if (stage != 4 && (l7prot_type == NULL || l7prot_id == NDPI_PROTOCOL_HTTP) && l7flow != NULL) {
                if (TcpGrbClientPkt(priv, pkt)) {
                    l7prot_id = nDPIPacket(pkt, l7flow, l7src, l7dst, ipv4);
                }
                else {
                    l7prot_id = nDPIPacket(pkt, l7flow, l7dst, l7src, ipv4);
                }
                if (l7prot_id != NDPI_PROTOCOL_UNKNOWN) {
                    stage++;
                    //l7prot_type = ndpi_prot_str[l7prot_id];
                }
            }
#ifdef XPL_CHECK_CODE
            if (pkt->raw_len != 0 && ((pkt->raw + pkt->raw_len) < pkt->data)) {
                LogPrintf(LV_OOPS, "TCP data location error %p %p %lu %lu", pkt->raw, pkt->data, pkt->raw_len, pkt->len);
                ProtStackFrmDisp(pkt->stk, TRUE);
                exit(-1);
            }
            if (pkt->raw_len != 0 && (pkt->data + pkt->len) > (pkt->raw + pkt->raw_len)) {
                LogPrintf(LV_OOPS, "TCP data dim error %p %p %lu %lu", pkt->raw, pkt->data, pkt->raw_len, pkt->len);
                ProtStackFrmDisp(pkt->stk, TRUE);
                exit(-1);
            }
#endif

#if GRB_FILE
            pckt_header.caplen = pkt->raw_len;
            pckt_header.len = pkt->raw_len;
            pckt_header.ts.tv_sec = pkt->cap_sec;
            pckt_header.ts.tv_usec = pkt->cap_usec;
            if (fd_pcap != -1) {
                write(fd_pcap, (char *)&pckt_header, sizeof(struct pcap_pkthdr));
                write(fd_pcap, (char *)pkt->raw, pkt->raw_len);
            }
#endif
        }
        else {
#if GRB_FILE || GRB_CHECK_LOST
            LogPrintf(LV_WARNING, "Packet Lost (size:%lu)", pkt->len);
            ProtStackFrmDisp(pkt->stk, TRUE);
#endif
        }
        if (thrs != NULL) {
            /* check stream to find text */
            if (lost.uint8 == FALSE && pkt->len != 0) {
                if (threshold + pkt->len > TCP_GRB_THRESHOLD) {
                    if (txt_data == FALSE) {
                        /* text flow */
                        txt_data = TcpGrbMajorityText(thrs, threshold);
                        if (txt_data == FALSE) {
                            xfree(thrs);
                            thrs = NULL;
                            threshold = 0;
                        }
                        else {
                            sprintf(txt_file, "%s/%s/tcp_grb_%lu_%p_%i.txt", ProtTmpDir(), TCP_GRB_TMP_DIR, time(NULL), txt_file, incr++);
                            txt_fp = fopen(txt_file, "w");
                            if (txt_fp != NULL) {
                                TcpGrbText(txt_fp, thrs, threshold);
                                threshold = 0;
                                memcpy(thrs+threshold, pkt->data,  pkt->len);
                                threshold += pkt->len;
                                thrs[threshold] = '\0';
                            }
                            else {
                                LogPrintf(LV_ERROR, "Unable to open file: %s", txt_file);
                                txt_data = FALSE;
                                xfree(thrs);
                                thrs = NULL;
                                threshold = 0;
                            }
                        }
                    }
                    else {
                        TcpGrbText(txt_fp, thrs, threshold);
                        threshold = 0;
                        memcpy(thrs+threshold, pkt->data,  pkt->len);
                        threshold += pkt->len;
                        thrs[threshold] = '\0';
                    }
                }
                else {
                    memcpy(thrs+threshold, pkt->data,  pkt->len);
                    threshold += pkt->len;
                    thrs[threshold] = '\0';
                }
            }
        }
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }
    
    /* text flows */
    if (thrs != NULL) {
        if (txt_data == FALSE) {
            /* text flow */
            if (TcpGrbMajorityText(thrs, threshold) == TRUE) {
                sprintf(txt_file, "%s/%s/tcp_grb_%lu_%p_%i.txt", ProtTmpDir(), TCP_GRB_TMP_DIR, time(NULL), txt_file, incr++);
                txt_fp = fopen(txt_file, "w");
            }
        }
        if (txt_fp != NULL) {
            TcpGrbText(txt_fp, thrs, threshold);
        }
        xfree(thrs);
    }
    
    /* ndpi free */
    if (l7flow != NULL) {
        xfree(l7flow);
        xfree(l7src);
        xfree(l7dst);
    }
    if (l7prot_type == NULL)
        l7prot_type = "Unknown";

    /* tcp reset */
    if (first_lost && (count < 5 || flow_size == 0)) {
        if (txt_fp != NULL) {
            fclose(txt_fp);
            remove(txt_file);
            txt_fp = NULL;
        }
    }
    else {
        if (txt_fp != NULL) {
            fclose(txt_fp);
            /* insert data */
            GrbPei(ppei, l7prot_type, flow_size, txt_file, &cap_sec, &end_cap);
            /* insert pei */
            PeiIns(ppei);
        }
        else  {
            /* insert data */
            GrbPei(ppei, l7prot_type, flow_size, NULL, &cap_sec, &end_cap);
            /* insert pei */
            PeiIns(ppei);
        }
    }
    /* end */
#if GRB_FILE
    if (fd_pcap != -1)
        close(fd_pcap);
#endif
    
    DMemFree(priv);

    LogPrintf(LV_DEBUG, "TCP->%s garbage... bye bye  fid:%d count:%i", l7prot_type, flow_id, count);

    return NULL;
}


int DissecRegist(const char *file_cfg)
{
    proto_heury_dep hdep;
    pei_cmpt peic;
    char cfg[TCP_GRB_FILENAME_PATH_SIZE];

    memset(&hdep, 0, sizeof(proto_heury_dep));
    memset(&peic, 0, sizeof(pei_cmpt));
 
    /* protocol name */
    ProtName("TCP garbage", "tcp-grb");

    /* dep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = TcpGrbCheck;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "l7prot";
    peic.desc = "L7 protocol march";
    ProtPeiComponent(&peic);

    peic.abbrev = "txt";
    peic.desc = "Text file";
    ProtPeiComponent(&peic);

    peic.abbrev = "size";
    peic.desc = "Flow total size";
    ProtPeiComponent(&peic);
    
    if (CfgParamInt(file_cfg, TCP_GRB_PKT_LIMIT_CFG, &limit_pkts) != 0)
        limit_pkts = TCP_GRB_PKT_LIMIT;
    
    /* dissectors subdissectors registration */
    ProtDissectors(NULL, TcpGrbDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char tmp_dir[256];
    unsigned short i;
    NDPI_PROTOCOL_BITMASK all;

    /* part of file name */
    incr = 0;

    /* info id */
    ppp_id = ProtId("ppp");
    eth_id = ProtId("eth");
    ip_id = ProtId("ip");
    ipv6_id = ProtId("ipv6");
    tcp_id = ProtId("tcp");
    if (ip_id != -1) {
        ip_dst_id = ProtAttrId(ip_id, "ip.dst");
        ip_src_id = ProtAttrId(ip_id, "ip.src");
        ip_offset_id = ProtAttrId(ip_id, "ip.offset");
    }
    if (ipv6_id != -1) {
        ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
        ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
        ipv6_offset_id = ProtAttrId(ipv6_id, "ipv6.offset");
    }
    if (tcp_id != -1) {
        port_dst_id = ProtAttrId(tcp_id, "tcp.dstport");
        port_src_id = ProtAttrId(tcp_id, "tcp.srcport");
        lost_id = ProtAttrId(tcp_id, "tcp.lost");
    }
    tcp_grb_id = ProtId("tcp-grb");
    
    /* pei id */
    pei_l7protocol_id = ProtPeiComptId(tcp_grb_id, "l7prot");
    pei_txt_id = ProtPeiComptId(tcp_grb_id, "txt");
    pei_size_id = ProtPeiComptId(tcp_grb_id, "size");
    
    /* tmp directory */
    sprintf(tmp_dir, "%s/%s", ProtTmpDir(), TCP_GRB_TMP_DIR);
    mkdir(tmp_dir, 0x01FF);

    /* ndpi */
    pthread_mutex_init(&ndpi_mux, NULL);
    ndpi = ndpi_init_detection_module(NDPI_TICK_RES, nDPImalloc, nDPIfree, nDPIPrintf);
    if (ndpi == NULL) {
        LogPrintf(LV_ERROR, "nDPi initializzation failed");

        return -1;
    }
    /* enable all protocols */
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi, &all);
    ndpi_proto_size = ndpi_detection_get_sizeof_ndpi_id_struct();
    ndpi_flow_struct_size = ndpi_detection_get_sizeof_ndpi_flow_struct();

    return 0;
}
