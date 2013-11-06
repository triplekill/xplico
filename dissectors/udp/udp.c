/* udp.c
 * UDP dissector
 *
 * $Id: $
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

#include <arpa/inet.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "ipproto.h"
#include "in_cksum.h"
#include "log.h"
#include "configs.h"

static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int prot_id;
static int src_id;
static int dst_id;

static unsigned short udphdr_len;

static packet* UdpDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val, ipv6_src, ipv6_dst;
    struct udphdr *udp;
    unsigned short len;
    unsigned int src, dst;
    vec_t cksum_vec[4];
    unsigned int phdr[2];
    unsigned short computed_cksum;

    /* packet len */
    if (pkt->len < udphdr_len) {
        LogPrintf(LV_WARNING, "UDP malformed packet");
        ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);

        return NULL;
    }

    udp = (struct udphdr *)pkt->data;
    len =  ntohs(udp->len);

    /* check lenght packet */
    if (pkt->len < len || len < sizeof(struct udphdr)) {
        LogPrintf(LV_WARNING, "UDP packet length error (udp:%i pkt:%i udp_header:%i)", len, pkt->len, sizeof(struct udphdr));
        ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);

        return NULL;
    }

    /* udp packet do not require a checksum when the cksum is == 0 */
    if (udp->check != 0) {
        /* check consistence and checksum */
        if (ProtFrameProtocol(pkt->stk) == ip_id) {
            /* IPV4 */
            ProtGetAttr(pkt->stk, ip_src_id, &val);
            src = val.uint32;
            ProtGetAttr(pkt->stk, ip_dst_id, &val);
            dst = val.uint32;
#if (XPL_DIS_IP_CHECKSUM == 0)
            cksum_vec[0].ptr = (const unsigned char *)&src;
            cksum_vec[0].len = 4;
            cksum_vec[1].ptr = (const unsigned char *)&dst;
            cksum_vec[1].len = 4;
            cksum_vec[2].ptr = (const unsigned char *)&phdr;
            phdr[0] = htonl((IP_PROTO_UDP<<16) + pkt->len);
            cksum_vec[2].len = 4;
            cksum_vec[3].ptr = (unsigned char *)pkt->data;
            cksum_vec[3].len = pkt->len;
            computed_cksum = in_cksum(&cksum_vec[0], 4);
            if (computed_cksum != 0) {
                LogPrintf(LV_WARNING, "UDP packet chechsum error 0x%x", computed_cksum);
                ProtStackFrmDisp(pkt->stk, TRUE);
                PktFree(pkt);
                
                return NULL;
            }
#endif
        }
        else {
            /* IPv6 */
            ProtGetAttr(pkt->stk, ipv6_src_id, &ipv6_src);
            ProtGetAttr(pkt->stk, ipv6_dst_id, &ipv6_dst);
#if (XPL_DIS_IP_CHECKSUM == 0)
            cksum_vec[0].ptr = (const unsigned char *)&ipv6_src.ipv6;
            cksum_vec[0].len = 16;
            cksum_vec[1].ptr = (const unsigned char *)&ipv6_dst.ipv6;
            cksum_vec[1].len = 16;
            cksum_vec[2].ptr = (const unsigned char *)&phdr;
            phdr[0] = htonl(pkt->len);
            phdr[1] = htonl(IP_PROTO_UDP);
            cksum_vec[2].len = 8;
            
            cksum_vec[3].ptr = (unsigned char *)pkt->data;
            cksum_vec[3].len = pkt->len;
            computed_cksum = in_cksum(&cksum_vec[0], 4);
            if (computed_cksum != 0) {
                LogPrintf(LV_WARNING, "UDP packet chechsum error 0x%x", computed_cksum);
                ProtStackFrmDisp(pkt->stk, TRUE);
                PktFree(pkt);
                
                return NULL;
            }
#endif
        }
    }

    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;
    
    /* set attribute */
    val.uint32 = ntohs(udp->source);
    ProtInsAttr(frame, src_id, &val);
    val.uint32 = ntohs(udp->dest);
    ProtInsAttr(frame, dst_id, &val);
        
    /* pdu */
    pkt->data += udphdr_len;
    pkt->len = len - udphdr_len;

    return pkt;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("User Datagram Protocol", "udp");

    /* source */
    info.name = "Source port";
    info.abbrev = "udp.srcport";
    info.type = FT_UINT16;
    src_id = ProtInfo(&info);

    /* destination */
    info.name = "Destination port";
    info.abbrev = "udp.dstport";
    info.type = FT_UINT16;
    dst_id = ProtInfo(&info);

    /* dep: IP */
    dep.name = "ip";
    dep.attr = "ip.proto";
    dep.type = FT_UINT8;
    dep.val.uint8 = IP_PROTO_UDP;
    ProtDep(&dep);

    /* dep: IPv6 */
    dep.name = "ipv6";
    dep.attr = "ipv6.nxt";
    dep.type = FT_UINT8;
    dep.val.uint8 = IP_PROTO_UDP;
    ProtDep(&dep);

    /* rule ipv4 */
    //ProtRule("(((ip.src == pkt.ip.src) AND (udp.srcport == pkt.udp.srcport)) AND ((ip.dst == pkt.ip.dst) AND (udp.dstport == pkt.udp.dstport)))");
    ProtAddRule("((((ip.src == pkt.ip.src) AND (udp.srcport == pkt.udp.srcport)) AND ((ip.dst == pkt.ip.dst) AND (udp.dstport == pkt.udp.dstport))) OR (((ip.dst == pkt.ip.src) AND (udp.dstport == pkt.udp.srcport)) AND ((ip.src == pkt.ip.dst) AND (udp.srcport == pkt.udp.dstport))))");
    
    /* rule: ipv6 */
    ProtAddRule("((((ipv6.src == pkt.ipv6.src) AND (udp.srcport == pkt.udp.srcport)) AND ((ipv6.dst == pkt.ipv6.dst) AND (udp.dstport == pkt.udp.dstport))) OR (((ipv6.dst == pkt.ipv6.src) AND (udp.dstport == pkt.udp.srcport)) AND ((ipv6.src == pkt.ipv6.dst) AND (udp.srcport == pkt.udp.dstport))))");


    /* dissectors registration */
    ProtDissectors(UdpDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    ip_id = ProtId("ip");
    ipv6_id = ProtId("ipv6");
    prot_id = ProtId("udp");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    
    udphdr_len = sizeof(struct udphdr);

    return 0;
}
