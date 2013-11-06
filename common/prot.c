/* prot.c
 * protocol core function dissector
 *
 * $Id: $
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#include "configs.h"
#include "proto.h"
#include "dmemory.h"
#include "log.h"
#include "ftypes.h"
#include "rule.h"
#include "fthread.h"
#include "xplxml.h"
#include "grp_rule.h"
#include "grp_flows.h"
#include "config_param.h"

/** define */
#define FLOW_TIMEOUT         1800
//#define XPL_CHECK_CODE_SORT  1

/* local structures */
struct dis_arg {
    int fid;
    int pid;
};


/** external variables */
extern prot_desc *prot_tbl;
extern int prot_tbl_dim;


/** internal variables */
static time_t fto = FLOW_TIMEOUT;   /* flow timeout */
static int prot_to_forced = -1;     /* to improve */


static packet* ProtSearchDissec(packet *pkt, int *prot_id);

//#define ProtLock(a) ProtLockp(a, __FUNCTION__);
//volatile char *fn_c;
//static inline void ProtLockp(int prot_id, char *fn)
static inline void ProtLock(int prot_id)
{
    if (pthread_mutex_trylock(&prot_tbl[prot_id].mux) != 0) {
        if (prot_tbl[prot_id].ptrd_lock != pthread_self()) {
            pthread_mutex_lock(&prot_tbl[prot_id].mux);
        }
    }
    //fn_c = fn;
    //LogPrintf(LV_DEBUG, "ProtLock: %s:%i", fn, prot_tbl[prot_id].nesting);
    prot_tbl[prot_id].ptrd_lock = pthread_self();
    prot_tbl[prot_id].nesting++;    
}


static inline void ProtUnlock(int prot_id)
{
    prot_tbl[prot_id].nesting--;
    if (prot_tbl[prot_id].nesting == 0) {
        prot_tbl[prot_id].ptrd_lock = 0;
        pthread_mutex_unlock(&prot_tbl[prot_id].mux);
    }
}


static int ProtFlowTimeout(int id)
{
    int elm_chk, i, fnum;
    flow_d *ftbld;
    time_t gbl_time, ftime, pftime;
    int pid, cp;

    gbl_time = FlowGetGblTime();
    ProtLock(id);
    if (prot_tbl[id].tver == FALSE) {
        ProtUnlock(id);
        return 0;
    }
    prot_tbl[id].tver = FALSE; /* only in one place we set tver to TRUE */
    
    ftbld = prot_tbl[id].ftbl;
    elm_chk = 0;
    fnum = prot_tbl[id].flow_num;
    pid = FthreadSelfFlowId();
    for (i=0; i<prot_tbl[id].ftbl_dim && elm_chk<fnum; i++) {
        if (ftbld[i].fid != -1) {
            /* only the children of the flow which calls ProtFlowTimeout can be closed */
            if (ftbld[i].pfid == pid && FlowCallSubDis(ftbld[i].fid, FALSE) == FALSE) {
                ftime = FlowTimeQ(ftbld[i].fid);
                if (ftbld[i].pfid != -1) {
                    pftime = FlowTimeQ(ftbld[i].pfid);
                }
                else {
                    pftime = gbl_time;
                }
#warning "Improve timeout definition and function!!!!"
                if (pftime > ftime + fto) {
                    FlowClose(ftbld[i].fid);
                }
            }
            elm_chk++;
        }
    }
    ProtUnlock(id);

    /* to forced */
    if (prot_to_forced != -1) {
        cp = prot_to_forced;
        prot_to_forced = -1;
        ProtFlowTimeout(cp);
    }

    return 0;
}


int ProtFlowTimeOutForce(int prot_id)
{
    prot_to_forced = prot_id;
    
    return 0;
}


#ifdef FTBL_SORT
static void ProtCheckSort(int prot_id)
{
    int i;
    
    for (i=0; i<prot_tbl[prot_id].flow_num-1; i++) {
        if (prot_tbl[prot_id].ftbl[i].hash > prot_tbl[prot_id].ftbl[i+1].hash) {
            LogPrintf(LV_OOPS, "Sort error: %i->%lu => %i->%lu",
                      i, prot_tbl[prot_id].ftbl[i].hash, i+1, prot_tbl[prot_id].ftbl[i+1].hash);
            exit(-1);
        }
        if (prot_tbl[prot_id].ftbl[i].fid == prot_tbl[prot_id].ftbl[i+1].fid) {
            LogPrintf(LV_OOPS, "Sort error: %i->%lu => %i->%lu",
                      i, prot_tbl[prot_id].ftbl[i].fid, i+1, prot_tbl[prot_id].ftbl[i+1].fid);
# if XP_MEM_DEBUG
            exit(-1);
# endif
        }
    }
}
#endif


static int ProtAddFlow(int prot_id, int flow_id)
{
    flow_d *new;
    int i, dim;
    const pstack_f *nxt;
    unsigned long hash;
#ifdef FTBL_SORT
    int sup, inf, check, diff;
#endif
#if CHECK_SINGLE_RULE
    unsigned short metric, tmp_m;
    int j, rl;
#endif

    /* stack */
    nxt = FlowStack(flow_id);
    if (nxt == NULL) {
        LogPrintf(LV_ERROR, "Flow without stack!");
        return -1;
    }

#if CHECK_SINGLE_RULE
    /* to find correct rule from many rules */
    metric = USHRT_MAX;
    for (j=0; j<prot_tbl[prot_id].rule_num; j++) {
        tmp_m = RuleStkMetric(&prot_tbl[prot_id].rule[j], nxt);
        
        if (tmp_m < metric) {
            /* new rule */
            rl = j;
            metric = tmp_m;
        }
    }
# ifdef XPL_CHECK_CODE
    if (metric == USHRT_MAX) {
        LogPrintf(LV_OOPS, "Bug in function %s line: %d", __FILE__, __LINE__);
        exit(-1);  
    }
# endif
    hash = RuleStkHash(prot_tbl[prot_id].rule+rl, 1, nxt);
#else
    hash = RuleStkHash(prot_tbl[prot_id].rule, prot_tbl[prot_id].rule_num, nxt);
#endif

    if (prot_tbl[prot_id].ftbl_dim == prot_tbl[prot_id].flow_num) {
        /* extend table */
        dim = prot_tbl[prot_id].ftbl_dim + PROT_FLOW_DESC_ADD;
        new = xrealloc(prot_tbl[prot_id].ftbl, sizeof(flow_d)*dim);
        if (new == NULL) {
            LogPrintf(LV_ERROR, "Unable to allocate memory for protocol %s", prot_tbl[prot_id].name);
            return -1;
        }
        for (i=prot_tbl[prot_id].ftbl_dim; i<dim; i++) {
            new[i].fid = -1;
            new[i].stack = NULL;
            new[i].hash = 0;
            new[i].pfid = -1;
        }
        i = prot_tbl[prot_id].ftbl_dim;
        prot_tbl[prot_id].ftbl = new;
        prot_tbl[prot_id].ftbl_dim = dim;
    }
    else {
#ifndef FTBL_SORT
        /* search free descriptor */
        i = 0;
        while (prot_tbl[prot_id].ftbl[i].fid != -1) {
            i++;
#  ifdef XPL_CHECK_CODE
            if (i == prot_tbl[prot_id].ftbl_dim) {
                LogPrintf(LV_OOPS, "Bug in function %s line: %d", __FILE__, __LINE__);
                return -1;
            }
#  endif
        }
#endif
    }

#ifdef FTBL_SORT
    /* search position */
    if (prot_tbl[prot_id].flow_num) {
#  if defined(XPL_CHECK_CODE) && defined(XPL_CHECK_CODE_SORT)
        ProtCheckSort(prot_id);
#  endif
        sup = 0;
        diff = 0;
        inf = prot_tbl[prot_id].flow_num - 1;
        do {
            if (inf - sup == 1)
                diff++;
            check = (sup+inf)>>1;
#  ifdef XPL_CHECK_CODE
            if (prot_tbl[prot_id].ftbl[check].fid == -1) {
                LogPrintf(LV_OOPS, "Bug in function %s line: %d", __FILE__, __LINE__);
                exit(-1);
                return -1;
            }
#  endif
            if (prot_tbl[prot_id].ftbl[check].hash >= hash) {
                inf = check;
            }
            else {
                sup = check;
            }
        } while (inf != sup && diff != 2);
        if (prot_tbl[prot_id].ftbl[inf].hash >= hash) {
            for (i=prot_tbl[prot_id].flow_num; i>inf; i--) {
                xmemcpy(prot_tbl[prot_id].ftbl+i, prot_tbl[prot_id].ftbl+(i-1), sizeof(flow_d));
            }
            /* insert new element in 'inf'*/
            i = inf;
        }
        else {
            i = prot_tbl[prot_id].flow_num;
        }
    }
    else
        i = 0;
#endif

    prot_tbl[prot_id].ftbl[i].fid = flow_id;
    prot_tbl[prot_id].ftbl[i].stack = nxt;
    prot_tbl[prot_id].ftbl[i].hash = hash;
    prot_tbl[prot_id].ftbl[i].pfid = ProtParent(nxt);
#if CHECK_SINGLE_RULE
    /* rule for this flow */
    prot_tbl[prot_id].ftbl[i].rule_id = rl;
#endif

    prot_tbl[prot_id].flow_num++;

#ifdef FTBL_SORT
#  if defined(XPL_CHECK_CODE) && defined(XPL_CHECK_CODE_SORT)
    ProtCheckSort(prot_id);
#  endif
#endif

    return i;
}


#define RL_LOCK_NEST   0 /* if is necesary nesting in dinamic protocol rule */

static inline void ProtRuleLock(int prot_id)
{
#if RL_LOCK_NEST == 1
    if (pthread_mutex_trylock(&prot_tbl[prot_id].rl_mux) != 0) {
        if (prot_tbl[prot_id].rl_ptrd_lock != pthread_self()) {
            pthread_mutex_lock(&prot_tbl[prot_id].rl_mux);
        }
    }
    prot_tbl[prot_id].rl_ptrd_lock = pthread_self();
    prot_tbl[prot_id].rl_nesting++;
#else
    pthread_mutex_lock(&prot_tbl[prot_id].rl_mux);
#endif
}


static inline void ProtRuleUnlock(int prot_id)
{
#if RL_LOCK_NEST == 1
    prot_tbl[prot_id].rl_nesting--;
    if (prot_tbl[prot_id].rl_nesting == 0) {
        prot_tbl[prot_id].rl_ptrd_lock = 0;
        pthread_mutex_unlock(&prot_tbl[prot_id].rl_mux);
    }
#else
    pthread_mutex_unlock(&prot_tbl[prot_id].rl_mux);
#endif
}


static void* ProtThreadPkt(void *arg)
{
    int pid;
    int fid;
    packet *pkt;

    pid = ((struct dis_arg *)arg)->pid;
    fid = ((struct dis_arg *)arg)->fid;
    DMemFree(arg);
    FthreadSync();

    pkt = FlowGetPkt(fid);
    while (pkt != NULL) {
        ProtDissec(pid, pkt);
        pkt = FlowGetPkt(fid);
    }

#ifdef XPL_CHECK_CODE
    if (FlowIsEmpty(fid) == FALSE) {
        LogPrintf(LV_OOPS, "Bug in %s:%i", __FILE__, __LINE__); 
    }
#endif

    FlowDelete(fid);

    FthreadEnd();

    return NULL;
}


static void* ProtThreadFlow(void *arg)
{
    int pid, flow_pid;
    int fid, orig;
    int thrid;
    packet *pkt;
    FlowDissector  FlowDis;
    bool sub;

    pid = ((struct dis_arg *)arg)->pid;
    flow_pid = pid;
    orig = fid = ((struct dis_arg *)arg)->fid;
    DMemFree(arg);
    FthreadSync();

    thrid = FlowThreadId(fid);
#ifdef XPL_CHECK_CODE
    if (thrid == -1) {
        LogPrintf(LV_OOPS, "Thread of flow (%d->%s) don't have thread id", fid, FlowName(fid));
        exit(-1);
    }
#endif

    FlowDis = prot_tbl[pid].FlowDis;
    do {
        sub = FALSE;
        pkt = FlowDis(fid);
        /* search next dissector */
        if (pkt != NULL) {
            pid = pkt->stk->pid;
            pkt = ProtSearchDissec(pkt, &pid);
            if (pid != -1) {
                sub = TRUE; /* data to be processed */
                ProtDissec(pid, pkt);
                pkt = NULL;
            }
        }
        /* use default dissector */
        if (pkt != NULL) {
            sub = TRUE; /* data to be processed */
            if (prot_tbl[flow_pid].DflSubDis != NULL)
                pkt = prot_tbl[flow_pid].DflSubDis(pkt);
            if (pkt != NULL)
                PktFree(pkt);
        }
        
        fid = FthreadFlow(thrid);  /* it is permited delete a flow only inside a dissector not inside this cicle */
        
    } while (fid != -1 && FlowInElabor(fid) == TRUE && (FlowGrpIsEmpty(fid) == FALSE || FlowPrivGet(fid) != NULL) && sub == TRUE);

    /* check if close */
    if (fid != -1) {
        /* check if all flow in the group are closed */
        if (FlowGrpIsEmpty(fid) == FALSE) {
            LogPrintf(LV_WARNING, "Dissector teminated without waiting for closure and consume all packet in its flow (%i)", fid);
            while (fid != -1 && FlowGrpIsEmpty(fid) == FALSE) {
                if (FlowIsEmpty(fid)) {
                    FlowDelete(fid);
                }
                else {
                    FlowDettach(fid);
                }
                fid = FthreadFlow(thrid);
            }
        }
        
        while (fid != -1 && FlowInElabor(fid) == TRUE) {
            FlowDelete(fid);
            fid = FthreadFlow(thrid);
        }
    }

    FthreadEnd();

    return NULL;
}


static int ProtThread(int prot_id, int flow_id)
{
    struct dis_arg *arg;
    int ret;

    if (prot_tbl[prot_id].GrpFlow != NULL) {
#warning "Grp flow to be implement"
        LogPrintf(LV_OOPS, "Functionality 'GroupFlow' not implemented");
        exit(-1);
        FlowPktCpReset(flow_id); // e anche gli altri
        prot_tbl[prot_id].GrpFlow(flow_id, NULL, 0);
        FlowPktCpReset(flow_id);
    }

    arg = DMemMalloc(sizeof(struct dis_arg));
    arg->pid = prot_id;
    arg->fid = flow_id;
    if (prot_tbl[prot_id].FlowDis != NULL) {
        ret = FthreadCreate(flow_id, ProtThreadFlow, arg);
    }
    else {
        ret = FthreadCreate(flow_id, ProtThreadPkt, arg);
    }
    
    return ret;
}


/* it is used only fro search and  lauch thread */
int ProtSearchHeuDissec(int id, int flow_id)
{
    int i, ret;
    unsigned long pktnum;
    bool cls;

    ret = -1;
    pktnum = FlowPktNum(flow_id);
    cls = FlowIsClose(flow_id); /* bossible deadlock */
    /* search heurist dissector */
    for (i=0; i<prot_tbl[id].stbl_dim; i++) {
        if (prot_tbl[id].stbl[i].heu_dep != NULL && (prot_tbl[id].stbl[i].heu_dep->pktlim >= pktnum || cls)) {
            /* ProtCheck in heu_dep is allayse different from NULL, see ProtHeuDep */
            FlowPktCpReset(flow_id);
            if (prot_tbl[id].stbl[i].heu_dep->ProtCheck(flow_id) == TRUE) {
                FlowPktCpReset(flow_id);
                /* set name of protocol */
                FlowSetName(flow_id, prot_tbl[id].stbl[i].id);

                ProtRunFlowInc(prot_tbl[id].stbl[i].id);
                
                /* create a group */
                if (prot_tbl[prot_tbl[id].stbl[i].id].grp == TRUE) {
                    FlowGrpCreate(flow_id);
                }
                
                /* launch thread */
                if (ProtThread(prot_tbl[id].stbl[i].id, flow_id) != 0) {
                    LogPrintf(LV_ERROR, "Unable to start thread (%d)", FthreadRunning());
                }
                ret = 0;
                break;
            }
            FlowPktCpReset(flow_id);
        }
    }

    return ret;
}


static packet* ProtSearchDissec(packet *pkt, int *prot_id)
{
    volatile int id = *prot_id;
    int i, j, ret, elm_chk;
    flow_d *ftbld;
    int flow_id, flow_par, flow_par_c, gpflow_id;
    pstack_f *flame_stk;
    int flowd_id;
    bool create, link;
    int flow_num;
    int elm_start, elm_stop;
    int prot;
    prot_rule *grule, *pre_rule;
#ifdef FTBL_SORT
    unsigned long hash;
    int sup, inf, check, diff;
#endif
#if CHECK_SINGLE_RULE
    unsigned short metric, tmp_m;
    int rl;
#endif

#ifdef XPL_CHECK_CODE
    if (pkt == NULL) {
        LogPrintf(LV_FATAL, "Packet NULL in %s", __FUNCTION__);
        exit(-1);
    }
    if (id == -1) {
        LogPrintf(LV_FATAL, "Protocol ID error", __FUNCTION__);
        ProtStackFrmDisp(pkt->stk, TRUE);
        exit(-1);
    }
#endif
    
    *prot_id = -1;
    if (prot_tbl[id].flow == FALSE) {
        /* packet dissector */
        for (i=0; i<prot_tbl[id].stbl_dim; i++) {
            if (FTCmp(&(pkt->stk->attr[prot_tbl[id].stbl[i].sfpaid]),
                      &(prot_tbl[id].stbl[i].dep->val), prot_tbl[id].stbl[i].dep->type,
                      prot_tbl[id].stbl[i].dep->op, &(prot_tbl[id].stbl[i].dep->opd)) == 0) {
                id = prot_tbl[id].stbl[i].id;
                *prot_id = id;
                break;
            }
        }
    }
    else {
        /* this dissector is a node of flows and so it is a flow dissector */
        /* search flow if it exist that match prtocol rule */
        /* actual flow */
        pkt->stk->flow = TRUE;
        flame_stk = pkt->stk->pfp;
        flow_par = -1;
        while (flame_stk != NULL && flame_stk->flow == FALSE) {
            flame_stk = flame_stk->pfp;
        }
        if (flame_stk != NULL)
            flow_par = flame_stk->flow_id; /* to improve at group flow */
        flow_id = -1;
        flowd_id = -1;
        elm_chk = 0;

        ProtLock(id);

        ftbld = prot_tbl[id].ftbl;
        flow_num = prot_tbl[id].flow_num; /* SubDis can close a flow */
        create = TRUE;
        prot_tbl[id].flwd_del = -1;

#ifdef FTBL_SORT
        if (prot_tbl[id].rule_sort && flow_num != 0) {
            /* check all elements */
#  if CHECK_SINGLE_RULE
            /* to find correct rule from many rules */
            metric = USHRT_MAX;
            for (j=0; j<prot_tbl[id].rule_num; j++) {
                tmp_m = RuleStkMetric(&prot_tbl[id].rule[j], pkt->stk);
                
                if (tmp_m < metric) {
                    /* new rule */
                    rl = j;
                    metric = tmp_m;
                }
            }
            hash = RuleStkHash(prot_tbl[id].rule+rl, 1, pkt->stk);
#  else
            hash = RuleStkHash(prot_tbl[id].rule, prot_tbl[id].rule_num, pkt->stk);
#  endif
            sup = 0;
            diff = 0;
            inf = prot_tbl[id].flow_num - 1;
            do {
                if (inf - sup == 1)
                    diff++;
                check = (sup+inf)>>1;
#ifdef XPL_CHECK_CODE
                if (prot_tbl[id].ftbl[check].fid == -1) {
                    LogPrintf(LV_OOPS, "Bug in function %s line: %d", __FILE__, __LINE__);
                    exit(-1);
                    return NULL;
                }
#endif
                if (prot_tbl[id].ftbl[check].hash >= hash) {
                    inf = check;
                }
                else {
                    sup = check;
                }
            } while (inf != sup && diff != 2);

            while (sup != 0 && prot_tbl[id].ftbl[sup].hash == hash)
                sup--;
            elm_start = sup;
            while (inf != prot_tbl[id].ftbl_dim && prot_tbl[id].ftbl[inf].hash == hash)
                inf++;
            elm_stop = inf;
        }
        else {
            /* check all elements */
            elm_start = 0;
            elm_stop = prot_tbl[id].ftbl_dim;
        }
#else
        elm_start = 0;
        elm_stop = prot_tbl[id].ftbl_dim;
#endif
        for (i=elm_start; i<elm_stop && elm_chk<flow_num; i++) {
            if (ftbld[i].fid != -1) {
                if (FlowIsClose(ftbld[i].fid) == FALSE) {
                    ret = -1;
                    /* check if flows have same parent flow */
                    flame_stk = ftbld[i].stack->pfp;
                    flow_par_c = -1;
                    while (flame_stk != NULL && flame_stk->flow == FALSE) {
                        flame_stk = flame_stk->pfp;
                    }
                    if (flame_stk != NULL)
                        flow_par_c = flame_stk->flow_id; /* to improve at group flow */
                    if (flow_par_c == flow_par) {
                        /* check rule */
#if CHECK_SINGLE_RULE
                        ret = RuleCheck(&prot_tbl[id].rule[ftbld[i].rule_id], ftbld[i].stack, pkt->stk);
#else
                        j = 0;
                        while (ret == -1 && j<prot_tbl[id].rule_num) {
                            ret = RuleCheck(&prot_tbl[id].rule[j++], ftbld[i].stack, pkt->stk);
                        }
#endif
                    }
                    if (ret == 1) {
                        flowd_id = i;
                        flow_id = ftbld[i].fid;
                        create = FALSE;
                        pkt->stk->flow_id = flow_id;
                        if (prot_tbl[id].SubDis != NULL) {
                            FlowCallSubDis(flow_id, TRUE); /* to block timeout */
                            prot_tbl[id].SubDis(flow_id, pkt);
                            /* FlowClose can be used in SubDis and then call ProtFlushFlow */
#ifdef FTBL_SORT
                            if (prot_tbl[id].flwd_del != -1) {
#  ifdef XPL_CHECK_CODE
                                if (flowd_id != prot_tbl[id].flwd_del) {
                                    LogPrintf(LV_OOPS, "Delete: flow descriptor error (a).");
                                    extern unsigned long crash_pkt_cnt;
                                    LogPrintf(LV_FATAL, "Last packet num: %lu", crash_pkt_cnt);
                                    printf("\nLast packet num: %lu\n", crash_pkt_cnt);
                                    exit(-1);
                                }
#  endif
                                flow_id = -1;
                                flowd_id = -1;
                            }
                            
#else
                            if (ftbld[flowd_id].fid == -1) {
                                flow_id = -1;
                                flowd_id = -1;
                            }
#endif
                        }
                        else {
                            FlowPutPkt(flow_id, pkt);
                        }
                        pkt = NULL;
                        break;
                    }
                }
                elm_chk++;
            }
#ifdef FTBL_SORT
            else {
                LogPrintf(LV_OOPS, "Flow table error");
                exit(-1);
            }
#endif
        }
        if (create == TRUE) {
            /* create new flow */
            flow_id = FlowCreate(pkt->stk);
            if (flow_id != -1) {
                /* flow descriptor */
                pkt->stk->flow_id = flow_id;
                flowd_id = ProtAddFlow(id, flow_id);
                if (flowd_id != -1) {
                    if (prot_tbl[id].SubDis != NULL) {
                        prot_tbl[id].SubDis(flow_id, pkt);
                        /* FlowClose can be used in SubDis and theme call ProtFlushFlow */
                        
#ifdef FTBL_SORT
                        if (prot_tbl[id].flwd_del != -1) {
#  ifdef XPL_CHECK_CODE
                            if (flowd_id != prot_tbl[id].flwd_del) {
                                LogPrintf(LV_OOPS, "Delete: flow descriptor error (b).");
                                extern unsigned long crash_pkt_cnt;
                                LogPrintf(LV_FATAL, "Last packet num: %lu", crash_pkt_cnt);
                                printf("\nLast packet num: %lu\n", crash_pkt_cnt);
                                exit(-1);
                            }
#  endif
                            flow_id = -1;
                        }
#else
                        flow_id = prot_tbl[id].ftbl[flowd_id].fid; /* if SubDis close the flow */
#endif
                    }
                    else {
                        FlowPutPkt(flow_id, pkt);
                    }
                    pkt = NULL;
                }
                else {
                    LogPrintf(LV_ERROR, "Unable to add new flows in protocol %s", prot_tbl[id].name);
                    ProtStackFrmDisp(pkt->stk, TRUE);
                    FlowClose(flow_id);
                    FlowDelete(flow_id);
                    flow_id = -1;
                }
            }
            else {
                LogPrintf(LV_ERROR, "Unable to create new flow");
            }
        }
        /* flow running */
        if (flow_id != -1) {
            ftbld = prot_tbl[id].ftbl;
#ifdef XPL_CHECK_CODE
            if (flowd_id == -1) {
                LogPrintf(LV_OOPS, "Flow descriptor don't exist.");
                ProtStackFrmDisp(FlowStack(flow_id), TRUE);
                exit(-1);
            }
            if (flow_id != ftbld[flowd_id].fid) {
                LogPrintf(LV_OOPS, "Flow descriptor 'differ' from flow ID. (%d: %d, %d->%d) ",
                          id, flow_id,  flowd_id, ftbld[flowd_id].fid);
                ProtStackFrmDisp(FlowStack(flow_id), TRUE);
                exit(-1);
            }
#endif
            if (FlowInElabor(flow_id) == FALSE) {
                create = FALSE;
                /* search inside protocol flow (group) waiting flows */
                ProtRuleLock(id);
                pre_rule = NULL;
                grule = prot_tbl[id].grule;
                while (grule != NULL && grule->verified == FALSE) {
                    link = FALSE;
                    if (GrpRuleCheck(&grule->rule, ftbld[flowd_id].stack) == TRUE) {
                        gpflow_id = GrpRuleFlowId(grule->id);
                        /* the flows must have the same parent flow */
                        if (ftbld[flowd_id].pfid == ProtParent(FlowStack(gpflow_id))) {
                            /* todo: verify packet with specific function */
#warning "To be improved"
                            link = TRUE;
                        }
                    }
                    /* all linking condictions are ok */
                    if (link == TRUE) {
                        create = TRUE;
                        LogPrintf(LV_DEBUG, "Agganciato rid:%i, fid:%i pfid:%i", grule->id, flow_id, gpflow_id);

                        /* set name of protocol */
                        prot = FlowProt(gpflow_id);
                        FlowSetName(flow_id, prot);

                        /* master protocol */
#ifdef PROT_GRP_COUNT
                        ProtRunFlowInc(prot);
#endif
                        FlowAddToGrp(gpflow_id, flow_id);
                        
                        /* rule verified */
                        grule->verified = TRUE;
                        /* move rule in the bottom of the queue with verified FALSE */
                        if (pre_rule != NULL && grule->nxt != NULL && grule->nxt->verified == FALSE) {
                            pre_rule->nxt = grule->nxt;
                            pre_rule = pre_rule->nxt;
                            while (pre_rule->nxt != NULL && grule->nxt->verified == FALSE) {
                                pre_rule = pre_rule->nxt;
                            }
                            grule->nxt = pre_rule->nxt;
                            pre_rule->nxt = grule;
                        }
                        else if (grule->nxt != NULL && grule->nxt->verified == FALSE) {
                            prot_tbl[id].grule = grule->nxt;
                            pre_rule = grule->nxt;
                            while (pre_rule->nxt != NULL && grule->nxt->verified == FALSE) {
                                pre_rule = pre_rule->nxt;
                            }
                            grule->nxt = pre_rule->nxt;
                            pre_rule->nxt = grule;
                        }
                        
                        /*important: at this moment grule may not exist in same queue position!!!!! */
#ifdef XPL_CHECK_CODE
                        if (FlowInElabor(flow_id) == FALSE) {
                            LogPrintf(LV_OOPS, "Bug in flows aggregations (%s:%i)", __FILE__, __LINE__);
                        }
#endif
                        break;
                    }
                    pre_rule = grule;
                    grule = grule->nxt;
                }
                ProtRuleUnlock(id);

                /* search dissector */
                if (create == FALSE) {
                    unsigned long pktnum;

                    pktnum = FlowPktNum(flow_id);
                    for (i=0; i!=prot_tbl[id].stbl_dim; i++) {
                        if (prot_tbl[id].stbl[i].dep != NULL && prot_tbl[id].stbl[i].dep->pktlim >= pktnum &&
                            FTCmp(&(ftbld[flowd_id].stack->attr[prot_tbl[id].stbl[i].sfpaid]), 
                                  &(prot_tbl[id].stbl[i].dep->val), prot_tbl[id].stbl[i].dep->type,
                                  prot_tbl[id].stbl[i].dep->op, &(prot_tbl[id].stbl[i].dep->opd)) == 0) {
                            /* if exist flow check function */
                            create = TRUE;
                            if (prot_tbl[id].stbl[i].dep->ProtCheck != NULL) {
                                FlowPktCpReset(flow_id);
                                create = prot_tbl[id].stbl[i].dep->ProtCheck(flow_id);
                                FlowPktCpReset(flow_id);
                            }
                            if (create == TRUE) {
                                /* set name of protocol */
                                FlowSetName(flow_id, prot_tbl[id].stbl[i].id);

                                ProtRunFlowInc(prot_tbl[id].stbl[i].id);
                                
                                /* create a group */
                                if (prot_tbl[prot_tbl[id].stbl[i].id].grp == TRUE) {
                                    FlowGrpCreate(flow_id);
                                }

                                /* launch thread */
                                if (ProtThread(prot_tbl[id].stbl[i].id, flow_id) != 0) {
                                    LogPrintf(LV_ERROR, "Unable to start thread (%d)", FthreadRunning());
                                    
                                }
                                break;
                            }
                        }
                    }
                }
                /* search heurist dissector and launch thread */
                if (create == FALSE) {
                    if (ProtSearchHeuDissec(id, flow_id) == 0)
                        create = TRUE;
                }
            }
        }
        ProtUnlock(id);
    }
    
    return pkt;
}


int ProtDissec(int prot_id, packet *pkt)
{
    PktDissector PktDis;
    packet *pkt_res;
    int id, pre_prot;

#ifdef XPL_CHECK_CODE
    if (pkt == NULL) {
        LogPrintf(LV_FATAL, "Packet NULL in %s", __FUNCTION__);
        exit(-1);
    }
#endif

    /* find dissector function */
    id = prot_id;
    PktDis = prot_tbl[id].PktDis;

    /* run */
    while (PktDis != NULL && pkt != NULL) {
#ifdef XPL_PEDANTIC_STATISTICS
        pthread_mutex_lock(&prot_tbl[id].cnt_mux);
        prot_tbl[id].pkt_tot++;
        pthread_mutex_unlock(&prot_tbl[id].cnt_mux);
#endif
        pkt_res = PktDis(pkt);
        if (pkt_res != NULL) {
            /* search new dissector */
            PktDis = NULL;
            id = pkt_res->stk->pid;
            pre_prot = id;
            pkt_res = ProtSearchDissec(pkt_res, &id);
            if (id != -1) {
                ProtFlowTimeout(id);
                PktDis = prot_tbl[id].PktDis;
            }
        }
        pkt = pkt_res;
    }
    
    ProtFlowTimeout(prot_id);
    
    /* if don't exist dissector or in error condiction */
    if (pkt != NULL) {
        if (prot_tbl[pre_prot].DflSubDis != NULL) {
            pkt = prot_tbl[pre_prot].DflSubDis(pkt);
        }
        if (pkt != NULL) {
            //ProtStackFrmDisp(pkt->stk, TRUE);
            PktFree(pkt);
        }
    }

    return 0;
}


packet* ProtDissecPkt(int prot_id, packet *pkt)
{
    PktDissector PktDis;
    int id;

#ifdef XPL_CHECK_CODE
    if (pkt == NULL) {
        LogPrintf(LV_WARNING, "Packet NULL in %s", __FUNCTION__);
        return NULL;
    }
#endif

    /* find dissector function */
    id = prot_id;
    PktDis = prot_tbl[id].PktDis;

    /* run only this dissector */
#ifdef XPL_PEDANTIC_STATISTICS
    pthread_mutex_lock(&prot_tbl[id].cnt_mux);
    prot_tbl[id].pkt_tot++;
    pthread_mutex_unlock(&prot_tbl[id].cnt_mux);
#endif
    if (PktDis != NULL)
        pkt = PktDis(pkt);
    else {
        LogPrintf(LV_WARNING, "Protocol without packet dissector function");
        PktFree(pkt);
        pkt = NULL;
    }
    ProtFlowTimeout(prot_id);
    
    return pkt;
}


const char *ProtGetName(int prot_id)
{
    if (0 < prot_id && prot_id < prot_tbl_dim)
        return prot_tbl[prot_id].name;
    else
        return NULL;
}


bool ProtIsNode(int prot_id)
{
    return prot_tbl[prot_id].flow;
}


int ProtFlushFlow(int prot_id, int flow_id)
{
    int i, j, ret;

    ProtLock(prot_id);
    /* check flow descriptor */
    for (i=0, j=0; i<prot_tbl[prot_id].ftbl_dim && j<prot_tbl[prot_id].flow_num ; i++) {
        if (prot_tbl[prot_id].ftbl[i].fid != -1) {
            if (prot_tbl[prot_id].ftbl[i].fid == flow_id)
                break;
            j++;
        }
    }
    
    if (j != prot_tbl[prot_id].flow_num) {
        ret = 0;
        if (prot_tbl[prot_id].SubDis != NULL)
            prot_tbl[prot_id].SubDis(flow_id, NULL);

        /* flush is executed at the close of flow then we remove flow descritpor */
#ifdef FTBL_SORT
        prot_tbl[prot_id].flow_num--;
        xmemcpy(&(prot_tbl[prot_id].ftbl[i]), &(prot_tbl[prot_id].ftbl[i+1]),
                sizeof(flow_d)*(prot_tbl[prot_id].flow_num - i));

        prot_tbl[prot_id].flwd_del = i;
        i = prot_tbl[prot_id].flow_num;
        prot_tbl[prot_id].ftbl[i].fid = -1;
        prot_tbl[prot_id].ftbl[i].stack = NULL;
        prot_tbl[prot_id].ftbl[i].hash = 0;
        prot_tbl[prot_id].ftbl[i].pfid = -1;
#  if defined(XPL_CHECK_CODE) && defined(XPL_CHECK_CODE_SORT)
        ProtCheckSort(prot_id);
#  endif
#else
        prot_tbl[prot_id].ftbl[i].fid = -1;
        prot_tbl[prot_id].ftbl[i].stack = NULL;
        prot_tbl[prot_id].ftbl[i].hash = 0;
        prot_tbl[prot_id].ftbl[i].pfid = -1;
        prot_tbl[prot_id].flow_num--;
#endif
    }
    else {
        LogPrintf(LV_ERROR, "Flow %s is not in protocol %s", FlowName(flow_id), prot_tbl[prot_id].name);
        ret = -1;
    }    

    ProtUnlock(prot_id);

    return ret;
}


int ProtOpenFlow(void)
{
    int i, res;

    /* it is not atomic! */
    res = 0;
    for (i=0; i<prot_tbl_dim; i++) {
        res += prot_tbl[i].flow_num;
    }

    return res;
}


int ProtId(char *name)
{
    int i;

    /* search protocol */
    for (i=0; i<prot_tbl_dim; i++) {
        if (strcmp(name, prot_tbl[i].name) == 0)
            break;
    }
    if (i == prot_tbl_dim)
        return -1;

    return i;
}


int ProtAttrId(int pid, char *attr)
{
    int i;
    
    if (pid == -1)
        return -1;

    /* search attribute id */
    for (i=0; i<prot_tbl[pid].info_num; i++) {
        if (strcmp(attr, prot_tbl[pid].info[i].abbrev) == 0)
            break;
    }
    if (i == prot_tbl[pid].info_num)
        return -1;

    return i;
}


enum ftype ProtAttrType(int pid, int attr_id)
{
    enum ftype tp;

    tp = FT_NONE;
    
    if (attr_id > -1 && attr_id < prot_tbl[pid].info_num)
        tp = prot_tbl[pid].info[attr_id].type;

    return tp;
}


const char *ProtAttrName(int pid, int attr_id)
{
    char *name;

    name = NULL;
    
    if (attr_id > -1 && attr_id < prot_tbl[pid].info_num)
        name = prot_tbl[pid].info[attr_id].abbrev;

    return name;
}


int ProtFrameSize(int prot_id)
{
    return prot_tbl[prot_id].pstack_sz;
}


pstack_f *ProtCreateFrame(int prot_id)
{
    pstack_f *frame;
    int size;

    size = prot_tbl[prot_id].pstack_sz;
    frame = DMemMalloc(size);
    if (frame == NULL)
        return NULL;

    memset(frame, 0, size);
    frame->pid = prot_id;
    frame->flow = prot_tbl[prot_id].flow;
    frame->flow_id = -1;
    frame->pfp = NULL;
    frame->gstack = NULL;

    return frame;
}


pstack_f *ProtCopyFrame(const pstack_f *stk, bool all)
{
    const pstack_f *next;
    pstack_f *frame, *new;
    int size, i, nv;

    new = NULL;
    frame = NULL;
    next = stk;
    do {
        size = prot_tbl[next->pid].pstack_sz;
        if (new == NULL) {
            frame = DMemMalloc(size);
            memset(frame, 0, size);
            new = frame;
        }
        else {
            frame->pfp = DMemMalloc(size);
            memset(frame->pfp, 0, size);
            frame = frame->pfp;
        }
        if (frame == NULL) {
            frame = new;
            while (frame != NULL) {
                new = frame->pfp;
                DMemFree(frame);
                frame = new;
            }
                
            return NULL;
        }
        
        frame->pid = next->pid;
        frame->flow = next->flow;
        frame->flow_id = next->flow_id;
        frame->pfp = NULL;
        if (next->gstack != NULL && all == TRUE) {
            frame->gstack = ProtCopyFrame(next->gstack, TRUE);
        }
        else {
            frame->gstack = NULL;
        }
        nv = prot_tbl[next->pid].info_num;
        for (i=0; i<nv; i++) {
            FTCopy(frame->attr+i, next->attr+i, prot_tbl[next->pid].info[i].type);
        }
        

        next = next->pfp;
    } while (next != NULL && all == TRUE); 

    return new;
}


bool ProtDiffFrame(const pstack_f *stk_a, const pstack_f *stk_b, bool all)
{
    const pstack_f *next_a;
    const pstack_f *next_b;
    int i, nv;
    
    if (stk_a == NULL || stk_b == NULL)
        return FALSE;
    
    next_a = stk_a;
    next_b = stk_b;
    do {
        if (next_a->pid != next_b->pid)
            return TRUE;
        if (next_a->flow != next_b->flow)
            return TRUE;
        if (next_a->flow_id != next_b->flow_id)
            return TRUE;
        if ((next_a->gstack != NULL || next_b->gstack != NULL) && all == TRUE) {
            if (ProtDiffFrame(next_a->gstack, next_b->gstack, TRUE) == TRUE)
                return TRUE;
        }
        nv = prot_tbl[next_a->pid].info_num;
        for (i=0; i<nv; i++) {
            if (FTCmp(next_a->attr+i, next_b->attr+i, prot_tbl[next_a->pid].info[i].type, FT_OP_EQ, NULL) != 0)
                return TRUE;
        }

        next_a = next_a->pfp;
        next_b = next_b->pfp;
    } while (next_a != NULL && next_b != NULL && all == TRUE); 

    if (next_a != NULL || next_b != NULL)
        return TRUE;
    
    return FALSE;
}


int ProtDelFrame(pstack_f *stk)
{
    pstack_f *nxt, *tmp;
    int nv, i;

    if (stk == NULL)
        return 0;
    
    nxt = stk;
    while (nxt != NULL) {
        if (nxt->gstack != NULL) {
            ProtDelFrame(nxt->gstack);
            nxt->gstack = NULL;
        }
        nv = prot_tbl[nxt->pid].info_num;
        for (i=0; i<nv; i++) {
            FTFree(nxt->attr+i, prot_tbl[nxt->pid].info[i].type);
        }
        tmp = nxt;
        nxt = nxt->pfp;
        DMemFree(tmp);
    }

    return 0;
}


int ProtInsAttr(pstack_f *frame, int id, ftval *val)
{
    if (frame == NULL)
        return -1;
    
    FTCopy(&frame->attr[id], val,  prot_tbl[frame->pid].info[id].type);

    return 0;
}


int ProtGetAttr(const pstack_f *frame, int id, ftval *val)
{
    if (frame == NULL)
        return -1;
    
    FTCopy(val, &frame->attr[id], prot_tbl[frame->pid].info[id].type);

    return 0;
}


int ProtPeiComptId(int pid, char *abbrev)
{
    int i;
    
    if (pid == -1)
        return -1;
    
    /* search component id */
    for (i=0; i<prot_tbl[pid].peic_num; i++) {
        if (strcmp(abbrev, prot_tbl[pid].peic[i].abbrev) == 0)
            break;
    }
    if (i == prot_tbl[pid].peic_num)
        return -1;

    return i;
}


inline int ProtFrameProtocol(const pstack_f *frame)
{
    return frame->pid;
}


inline const pstack_f* ProtGetNxtFrame(const pstack_f *frame)
{
    return frame->pfp;
}


inline int ProtSetNxtFrame(pstack_f *frame, pstack_f *nxt)
{
    frame->pfp = nxt;
    
    return 0;
}


void ProtStackFrmDisp(const pstack_f *frame, bool all)
{
    const pstack_f *next;
    int i, num;
    char *buff;
    int space = 0;
    char *resp[] = {"no", "yes"};
    char *space_c;
    
    num = 0;
    next = frame;
    buff = DMemMalloc(51200);
    space_c = buff + 50000; /* 1200 space char */
    memset(space_c, ' ', 1200); /* 1200 space char */
    space_c[1200-1] = '\0'; /* security */
    space_c[space] = '\0';
    while (next != NULL) {
        LogPrintf(LV_INFO, "%sframe %d - prot: %d,  flow: %s, id: %d -",
                  space_c, num, next->pid, resp[next->flow], next->flow_id);
        space_c[space] = ' ';
        space += 3;
        space_c[space] = '\0';
        for (i=0; i<prot_tbl[next->pid].info_num; i++) {
            LogPrintf(LV_INFO, "%s%s: %s", space_c, prot_tbl[next->pid].info[i].abbrev,
                      FTString(&next->attr[i], prot_tbl[next->pid].info[i].type, buff));
        }
        if (all == TRUE)
            next = next->pfp;
        else
            next = NULL;
        num++;
    }
    DMemFree(buff);
}


char *ProtStackFrmXML(const pstack_f *frame)
{
    char *xml_buf;
    int dim, len, i, j;
    const pstack_f *next, *nxt_flow;
    char *buff;

    i = 0;
    dim = 1024;
    nxt_flow = frame;
    len = 0;
    buff = DMemMalloc(10240);
    xml_buf = xmalloc(dim);
    strcpy(xml_buf+len, XPL_HEADER);
    len += strlen(XPL_HEADER);
    len += sprintf(xml_buf+len, XPL_GRP_FRAME_OPEN);
    do {
        dim += 1024;
        xml_buf = xrealloc(xml_buf, dim);
        len += sprintf(xml_buf+len, XPL_FLOW_OPEN, i);
        i++;
        next = nxt_flow;
        nxt_flow = next->gstack;
        while (next != NULL) {
            if (len > dim-4096) {
                dim += 4096;
                xml_buf = xrealloc(xml_buf, dim);
            }
            len += sprintf(xml_buf+len, XPL_FRAME_OPEN,  prot_tbl[next->pid].name);
            for (j=0; j<prot_tbl[next->pid].info_num; j++) {
                len += sprintf(xml_buf+len, XPL_PROP, prot_tbl[next->pid].info[j].abbrev,
                               FTString(&next->attr[j], prot_tbl[next->pid].info[j].type, buff));
            }
            strcpy(xml_buf+len, XPL_FRAME_CLOSE);
            len += strlen(XPL_FRAME_CLOSE);
            next = next->pfp;
        }
        strcpy(xml_buf+len, XPL_FLOW_CLOSE);
        len += strlen(XPL_FLOW_CLOSE);
    } while (nxt_flow != NULL);
    len += sprintf(xml_buf+len, XPL_GRP_FRAME_CLOSE);
    DMemFree(buff);

    return xml_buf;
}


/* wireshark filter frame representation */
char *ProtStackFrmFilter(const pstack_f *frame)
{
    char *filter_buf;
    int dim, len, i, j;
    const pstack_f *next;
    char *buff;
    bool add;

    i = 0;
    dim = 4096;
    next = frame;
    len = 0;
    buff = DMemMalloc(10240);
    filter_buf = xmalloc(dim);
    filter_buf[0] = '\0';
    while (next != NULL) {
        add = FALSE;
        if (len > dim-4096) {
            dim += 4096;
            filter_buf = xrealloc(filter_buf, dim);
        }
        if (strcmp(prot_tbl[next->pid].name, "ip") == 0) {
            add = TRUE;
        }
        else if (strcmp(prot_tbl[next->pid].name, "ipv6") == 0) {
            add = TRUE;
        }
        else if (strcmp(prot_tbl[next->pid].name, "udp") == 0) {
            add = TRUE;
        }
        else if (strcmp(prot_tbl[next->pid].name, "tcp") == 0) {
            add = TRUE;
        }
        
        if (add == TRUE) {
            for (j=0; j<prot_tbl[next->pid].info_num; j++) {
                if (strcmp(prot_tbl[next->pid].info[j].abbrev, "ip.src") == 0 ||
                    strcmp(prot_tbl[next->pid].info[j].abbrev, "ip.dst") == 0) {
                    if (len != 0) {
                        len += sprintf(filter_buf+len, " and ");
                    }
                    else {
                        len += sprintf(filter_buf+len, "( ");
                    }
                    len += sprintf(filter_buf+len, "ip.addr==%s",
                                   FTString(&next->attr[j], prot_tbl[next->pid].info[j].type, buff));
                }
                else if (strcmp(prot_tbl[next->pid].info[j].abbrev, "ipv6.src") == 0 ||
                    strcmp(prot_tbl[next->pid].info[j].abbrev, "ipv6.dst") == 0) {
                    if (len != 0) {
                        len += sprintf(filter_buf+len, " and ");
                    }
                    else {
                        len += sprintf(filter_buf+len, "( ");
                    }
                    len += sprintf(filter_buf+len, "ipv6.addr==%s",
                                   FTString(&next->attr[j], prot_tbl[next->pid].info[j].type, buff));
                }
                else if (strcmp(prot_tbl[next->pid].info[j].abbrev, "tcp.srcport") == 0 ||
                    strcmp(prot_tbl[next->pid].info[j].abbrev, "tcp.dstport") == 0) {
                    if (len != 0) {
                        len += sprintf(filter_buf+len, " and ");
                    }
                    else {
                        len += sprintf(filter_buf+len, "( ");
                    }
                    len += sprintf(filter_buf+len, "tcp.port==%s",
                                   FTString(&next->attr[j], prot_tbl[next->pid].info[j].type, buff));
                }
                else if (strcmp(prot_tbl[next->pid].info[j].abbrev, "udp.srcport") == 0 ||
                    strcmp(prot_tbl[next->pid].info[j].abbrev, "udp.dstport") == 0) {
                    if (len != 0) {
                        len += sprintf(filter_buf+len, " and ");
                    }
                    else {
                        len += sprintf(filter_buf+len, "( ");
                    }
                    len += sprintf(filter_buf+len, "udp.port==%s",
                                   FTString(&next->attr[j], prot_tbl[next->pid].info[j].type, buff));
                }
            }
        }
        next = next->pfp;
    }
    if (len != 0) {
        len += sprintf(filter_buf+len, " )");
    }
    DMemFree(buff);

    return filter_buf;
}


PktDissector ProtPktDis(int prot_id)
{
    return prot_tbl[prot_id].PktDis;
}


FlowDissector ProtFlowDis(int prot_id)
{
    return prot_tbl[prot_id].FlowDis;
}


PktDissector ProtPktDefaultDis(int prot_id)
{
    return prot_tbl[prot_id].DflSubDis;
}


int ProtGrpRuleIns(int prot_id, int rule_id, const grp_rule *rule)
{
    prot_rule *new;
    int i;

    new = DMemMalloc(sizeof(prot_rule));
    new->id = rule_id;
    new->verified = FALSE;
    new->rule.num = rule->num;
    new->rule.or = xmalloc(sizeof(and_rule)*(rule->num));
    for (i=0; i!=rule->num; i++) {
        new->rule.or[i].and = rule->or[i].and;
        new->rule.or[i].num = rule->or[i].num;
    }
    new->nxt = NULL;

    ProtRuleLock(prot_id);
    new->nxt = prot_tbl[prot_id].grule;
    prot_tbl[prot_id].grule = new;
    ProtRuleUnlock(prot_id);

    return 0;
}


int ProtGrpRuleRm(int prot_id, int rule_id)
{
    prot_rule *rule, *pre_rl;

    ProtRuleLock(prot_id);

    pre_rl = NULL;
    rule = prot_tbl[prot_id].grule;
    while (rule != NULL && rule->id != rule_id) {
        pre_rl = rule;
        rule = rule->nxt;
    }
#ifdef XPL_CHECK_CODE
    if (rule == NULL) {
        LogPrintf(LV_OOPS, "Bug in protocol rule (%s:%i)", __FILE__, __LINE__);
    }
    else
    {
#endif
        if (pre_rl == NULL)
            prot_tbl[prot_id].grule = rule->nxt;
        else
            pre_rl->nxt = rule->nxt;
        
        /* free memory */
        xfree(rule->rule.or);
        DMemFree(rule);

#ifdef XPL_CHECK_CODE
    }
#endif
    
    ProtRuleUnlock(prot_id);

    return 0;
}


int ProtStackSearchNode(const pstack_f *stk)
{
    int i, j, p_id;
    int elm_chk;
    flow_d *ftbld;
    pstack_f *flame_stk;
    int flow_id, flow_par, flow_par_c;
    int ret;

    if (stk == NULL && stk->flow == FALSE)
        return -1;

    /* node of flow parent of this stack */
    flame_stk = stk->pfp;
    flow_par = -1;
    while (flame_stk != NULL && flame_stk->flow == FALSE) {
        flame_stk = flame_stk->pfp;
    }
    if (flame_stk != NULL)
        flow_par = flame_stk->flow_id;

    p_id = stk->pid;
    elm_chk = 0;
    flow_id = -1;
    ProtLock(p_id);
    ftbld = prot_tbl[p_id].ftbl;
    for (i=0; i<prot_tbl[p_id].ftbl_dim && elm_chk<prot_tbl[p_id].flow_num; i++) {
        if (ftbld[i].fid != -1) {
            if (FlowIsClose(ftbld[i].fid) == FALSE && FlowInElabor(ftbld[i].fid) == FALSE) {
                /* check if flows have same parent flow */
                flame_stk = ftbld[i].stack->pfp;
                flow_par_c = -1;
                while (flame_stk != NULL && flame_stk->flow == FALSE) {
                    flame_stk = flame_stk->pfp;
                }
                if (flame_stk != NULL)
                    flow_par_c = flame_stk->flow_id;
                if (flow_par_c == flow_par) {
                    /* check rule */
                    ret = -1;
                    j = 0;
                    while (ret == -1 && j<prot_tbl[p_id].rule_num) {
                        ret = RuleCheck(&prot_tbl[p_id].rule[j++], ftbld[i].stack, stk);
                    }
                    if (ret == 1) {
                        flow_id = ftbld[i].fid;
                        break;
                    }
                }
            }
            elm_chk++;
        }
    }
    ProtUnlock(p_id);

    return flow_id;
}


const pstack_f* ProtStackSearchProt(const pstack_f *stk, int pid)
{
    if (pid == -1)
        return NULL;

    while (stk != NULL && stk->pid != pid)
        stk = stk->pfp;

    return stk;
}


int ProtParent(const pstack_f *stk)
{
    const pstack_f *nxt;
    int i;

    i = -1;
    nxt = stk->pfp;
    while (nxt != NULL) {
        if (nxt->flow == TRUE) {
            i = nxt->flow_id;
            break;
        }
        nxt = nxt->pfp;
    }
    
    return i;
}


int ProtRunFlowInc(int prot_id)
{
    ProtLock(prot_id);

    prot_tbl[prot_id].flow_run++;
    prot_tbl[prot_id].flow_tot++;

    ProtUnlock(prot_id);

    return 0;
}


int ProtRunFlowDec(int prot_id)
{
    ProtLock(prot_id);

    prot_tbl[prot_id].flow_run--;
    
    ProtUnlock(prot_id);

    return 0;
}


int ProtRunningFlow(int prot_id)
{
    return prot_tbl[prot_id].flow_run;
}


unsigned long ProtTotFlow(int prot_id)
{
    return prot_tbl[prot_id].flow_tot;
}


int ProtStatus(void)
{
    int i;

    for (i=0; i<prot_tbl_dim; i++) {
#ifdef XPL_PEDANTIC_STATISTICS
        printf("%s: running: %i/%lu, subflow:%i/%i, tot pkt:%lu\n",
               prot_tbl[i].name, prot_tbl[i].flow_run, prot_tbl[i].flow_tot,
               prot_tbl[i].flow_num, prot_tbl[i].ftbl_dim, prot_tbl[i].pkt_tot);
#else
        printf("%s: running: %i/%lu, subflow:%i/%i\n",
               prot_tbl[i].name, prot_tbl[i].flow_run, prot_tbl[i].flow_tot,
               prot_tbl[i].flow_num, prot_tbl[i].ftbl_dim);
#endif
    }
    
    return 0;
}


unsigned short ProtLogMask(int prot_id)
{
    return prot_tbl[prot_id].log_mask;
}


const char* ProtLogName(int prot_id)
{
    return prot_tbl[prot_id].name;
}


#ifdef XPL_PEDANTIC_STATISTICS
int ProtPktFromNode(int prot_id, unsigned long pkt_tot)
{
    pthread_mutex_lock(&prot_tbl[prot_id].cnt_mux);
    if (prot_tbl[prot_id].FlowDis != NULL) /* ProtThreadPkt stated and ProtDissec has counted packet */
        prot_tbl[prot_id].pkt_tot += pkt_tot;
    pthread_mutex_unlock(&prot_tbl[prot_id].cnt_mux);
    
    return 0;
}

#endif

int ProtInit(const char *file_cfg)
{
    FILE *fp;
    char buffer[CFG_LINE_MAX_SIZE];
    char bufcpy[CFG_LINE_MAX_SIZE];
    char *param;
    int res, nl;
    time_t to;

    /* default values */
    fto = FLOW_TIMEOUT;
    prot_to_forced = -1;

    /* read config file params */
    if (file_cfg == NULL) {
        return 0;
    }
    
    /* search dir path */
    fp = fopen(file_cfg, "r");
    if (fp == NULL) {
        printf("error: unable to open file %s\n", file_cfg);
        return -1;
    }
    nl = 0;
    while (fgets(buffer, CFG_LINE_MAX_SIZE, fp) != NULL) {
        nl++;
        /* check all line */
        if (strlen(buffer)+1 == CFG_LINE_MAX_SIZE) {
            printf("error: Config file line more length to %d characters\n", CFG_LINE_MAX_SIZE);
            return -1;
        }
        /* check if line is a comment */
        if (!CfgParIsComment(buffer)) {
            /* flow silence timeout */
            param = strstr(buffer, CFG_PAR_FLOW_TIMEOUT);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_FLOW_TIMEOUT"=%lu %s", &to, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        printf("error: Config param error in line %d. Unknow param: %s\n", nl, bufcpy);
                        return -1;
                    }
                    fto = to;
                }
            }
        }
    }
    fclose(fp);

    return 0;
}


int ProtNumber(void)
{
    return prot_tbl_dim;
}


int ProtNodeLock(void)
{
    int i, j;
    bool locked;

    /* lock all protocols that can be a nod of flow */
    j = -1;
    locked = FALSE;
    do {
        for (i=0; i<prot_tbl_dim; i++) {
            /* lock all mutex */
            if (prot_tbl[i].flow == TRUE && i != j) {
                if (pthread_mutex_trylock(&prot_tbl[i].mux) != 0) {
                    if (prot_tbl[i].ptrd_lock != pthread_self()) {
                        /* mutex in use */
                        printf("Break: %i\n", i);
                        break;
                    }
                }
                prot_tbl[i].ptrd_lock = pthread_self();
                prot_tbl[i].nesting++;
            }
        }
        if (i != prot_tbl_dim) {
            //printf("Lock[%i]: 0->%i (%i)\n", prot_tbl_dim, i, j);
            /* one of mutex is used, unlock other mutex */
            if (j != -1 && j > i) {
                prot_tbl[j].nesting--;
                if (prot_tbl[j].nesting == 0) {
                    prot_tbl[j].ptrd_lock = 0;
                    pthread_mutex_unlock(&prot_tbl[j].mux);
                }
            }
            j = i;
            for (i=0; i<j; i++) {
                if (prot_tbl[i].flow == TRUE) {
                    prot_tbl[i].nesting--;
                    if (prot_tbl[i].nesting == 0) {
                        prot_tbl[i].ptrd_lock = 0;
                        pthread_mutex_unlock(&prot_tbl[i].mux);
                    }
                }
            }
            /* wait mutex */
            if (pthread_mutex_trylock(&prot_tbl[j].mux) != 0) {
                if (prot_tbl[j].ptrd_lock != pthread_self()) {
                    pthread_mutex_lock(&prot_tbl[j].mux);
                }
            }
            prot_tbl[j].ptrd_lock = pthread_self();
            prot_tbl[j].nesting++;
        }
        else {
            locked  = TRUE;
        }
    } while (locked == FALSE);

    return 0;
}


int ProtNodeUnlock(void)
{
    int i;

    for (i=0; i<prot_tbl_dim; i++) {
         /* unlock all mutex */
        if (prot_tbl[i].flow == TRUE) {
            prot_tbl[i].nesting--;
            if (prot_tbl[i].nesting == 0) {
                prot_tbl[i].ptrd_lock = 0;
                pthread_mutex_unlock(&prot_tbl[i].mux);
            }
        }
    }

    return 0;
}
