/* rule.c
 * function to convert string rule in code rule
 *
 * $Id: rule.c,v 1.8 2007/09/22 14:03:55 costa Exp $
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "configs.h"
#include "flow.h"
#include "proto.h"
#include "dmemory.h"
#include "rule.h"
#include "log.h"


extern prot_desc *prot_tbl;
extern int prot_tbl_dim;


static int RuleOperation(char *op)
{
    if (strcmp(op, FT_SOP_EQ) == 0) {
        return FT_OP_EQ;
    }

    return -1;
}


static int RuleElem(char *a, char *op, char *b, char *part)
{
    char *close;
    char *open;
    char end;
    int ret;

    /* verify element */
    close = strchr(part, ')');
    open = strchr(part+1, '(');
    if (close == NULL)
        return -1;
    if (open != NULL && close > open)
        return -1;
    end = close[0];
    close[0] = '\0';
    ret = -1;

    /* exstract element value */
    if (sscanf(part, "(%s %s %s)", a, op, b) == 3)
        ret = 0;
    else if (sscanf(part, "( %s %s %s )", a, op, b) == 3)
        ret = 0;

    close[0] = end;

    return ret;
}


static int RuleElementId(cmp_r *cmp, char *elm, bool stack)
{
    int i, j;
    char *fnd;

    /* search dissector attribute */
    if (stack == FALSE) {
        if (strncmp(elm, FLOW_RULE_PKT, strlen(FLOW_RULE_PKT)) != 0)
            return -1;
        fnd = elm+strlen(FLOW_RULE_PKT);
    }
    else
        fnd = elm;
    for (i=0; i<prot_tbl_dim; i++) {
        for (j=0; j<prot_tbl[i].info_num; j++) {
            if (strcmp(fnd, prot_tbl[i].info[j].abbrev) == 0) {
                if (stack == TRUE) {
                    cmp->prta_id = i;
                    cmp->atta_id = j;
                    cmp->type = prot_tbl[i].info[j].type;
                }
                else {
                    cmp->prtb_id = i;
                    cmp->attb_id = j;
                    if (cmp->type != prot_tbl[i].info[j].type) {
                        return -1;
                    }
                }
                return 0;
            }
        }
    }

    return -1;
}


int RuleConvert(flow_rule *rule)
{
    char *token, *old_tkn;
    char *bool1;
    char *bool2;
    char *a, *op, *b;
    char *src, *dest, *tmp;
    char snum[10];
    int len, ret, i, j;
    int oper, anum, bnum;

    /* setup */
    len = strlen(rule->rule);
    bool1 = xmalloc(len+1);
    bool2 = xmalloc(len+1);
    a = xmalloc(len+1);
    op = xmalloc(len+1);
    b = xmalloc(len+1);
    memset(bool1, 0, len+1);
    memset(bool2, 0, len+1);
    memset(a, 0, len+1);
    memset(op, 0, len+1);
    memset(b, 0, len+1);
    /* by default compare are equal */
    rule->cmp_eq = TRUE;

    /* compare rule part */
    old_tkn = rule->rule;
    LogPrintf(LV_DEBUG, "rule: %s", rule->rule);
    token = strchr(rule->rule, '(');
    while (token != NULL) {
        bool1 = strncat(bool1, old_tkn, token-old_tkn);
        memset(a, 0, len+1);
        memset(op, 0, len+1);
        memset(b, 0, len+1);
        ret = RuleElem(a, op, b, token);
        if (ret == 0) {
            /* operation check */
            oper = RuleOperation(op);
            if (oper == -1) {
                LogPrintf(LV_ERROR, "don't understand operation '%s'", op);
                xfree(bool1);
                xfree(bool2);
                xfree(a);
                xfree(op);
                xfree(b);
                return -1;
            }
            /* search protocol and protocol attribute */
            rule->cmp = xrealloc(rule->cmp, sizeof(cmp_r)*(rule->ncmp+1));
            memset(&rule->cmp[rule->ncmp], 0, sizeof(cmp_r));
            rule->cmp[rule->ncmp].simil = -1;
            ret = RuleElementId(&rule->cmp[rule->ncmp], a, TRUE);
            if (ret != 0) {
                LogPrintf(LV_WARNING, "don't find dissector attribute '%s'", a);
                xfree(bool1);
                xfree(bool2);
                xfree(a);
                xfree(op);
                xfree(b);
                return -1;
            }
            ret = RuleElementId(&rule->cmp[rule->ncmp], b, FALSE);
            if (ret != 0) {
                LogPrintf(LV_WARNING, "don't find dissector attribute '%s'", b);
                xfree(bool1);
                xfree(bool2);
                xfree(a);
                xfree(op);
                xfree(b);
                return -1;
            }
            rule->cmp[rule->ncmp].op = oper;
            if (oper != FT_OP_EQ)
                rule->cmp_eq = FALSE;
            sprintf(snum, "%d", rule->ncmp);
            rule->ncmp++;
            bool1 = strcat(bool1, snum);
            old_tkn = strchr(token, ')') + 1;
        }
        else
            old_tkn = token;
        token = strchr(token+1, '(');
    }
    bool1 = strcat(bool1, old_tkn);
    rule->nrules = rule->ncmp;
    LogPrintf(LV_DEBUG, "First step: %s", bool1);

    /* boolean rule part */
    i = 0;
    src = bool1;
    dest = bool2;
    while (strchr(src, '(') != NULL && strcmp(dest, src) != 0) {
        memset(dest, 0, len+1);
        old_tkn = src;
        token = strchr(src, '(');
        while (token != NULL) {
            dest = strncat(dest, old_tkn, token-old_tkn);
            memset(a, 0, len+1);
            memset(op, 0, len+1);
            memset(b, 0, len+1);
            ret = RuleElem(a, op, b, token);
            if (ret == 0) {
                /* search boolean result */
                anum = atoi(a);
                bnum = atoi(b);
                if (strcmp(op, FT_SOP_AND) == 0)
                    oper = 0;
                else if (strcmp(op, FT_SOP_OR) == 0)
                    oper = 1;
                else {
                    LogPrintf(LV_ERROR, "don't understand operation '%s'", op);
                    xfree(bool1);
                    xfree(bool2);
                    xfree(a);
                    xfree(op);
                    xfree(b);
                    return -1;
                }
                rule->bln = xrealloc(rule->bln, sizeof(bln_r)*(rule->nbln+1));
                memset(&rule->bln[rule->nbln], 0, sizeof(bln_r));
                rule->bln[rule->nbln].op = oper;
                rule->bln[rule->nbln].a = anum;
                rule->bln[rule->nbln].b = bnum;
                sprintf(snum, "%d", rule->nrules);
                rule->nbln++;
                rule->nrules++;
                dest = strcat(dest, snum);
                old_tkn = strchr(token, ')') + 1;
            }
            else
                old_tkn = token;
            token = strchr(token+1, '(');
        }
        dest = strcat(dest, old_tkn);
        tmp = src;
        src = dest;
        dest = tmp;
        i++;
        LogPrintf(LV_DEBUG, "Boolean step %d: %s", i, src);
    }
    rule->bres = xmalloc(sizeof(int)*rule->nrules);
    memset(rule->bres, 0, sizeof(int)*rule->nrules);
    /* check rule consistency */
    if (strchr(src, '(') != NULL) {
        xfree(bool1);
        xfree(bool2);
        xfree(a);
        xfree(op);
        xfree(b);

        return -1;
    }

    /* calculate simil cmp */
    for (i=0; i<rule->ncmp; i++) {
        for (j=i+1; j<rule->ncmp; j++) {
            if (rule->cmp[i].prta_id == rule->cmp[j].prta_id &&
                rule->cmp[i].prtb_id == rule->cmp[j].prtb_id &&
                rule->cmp[i].op == rule->cmp[j].op) {
                rule->cmp[i].simil = j;
                LogPrintf(LV_DEBUG, "Simil %d <---> %d", i, j);
                break;
            }
        }
    }

    /* clean */
    xfree(bool1);
    xfree(bool2);
    xfree(a);
    xfree(op);
    xfree(b);

    return 0;
}


int RuleCheck(flow_rule *rule, const pstack_f *ref, const pstack_f *eval)
{
    int *bres;
    int nrules;
    cmp_r *cmp;
    int ncmp;
    bln_r *bln;
    int nbln;
    int i, j, res;
    const pstack_f *ref_c;
    const pstack_f *eval_c;
    bool flow;

    /* init */
    bres = rule->bres;
    nrules = rule->nrules;
    cmp = rule->cmp;
    ncmp = rule->ncmp;
    bln = rule->bln;
    nbln = rule->nbln;
    memset(bres, -1, sizeof(int)*nrules);

    /* base element */
    j = 0;
    do {
        if (bres[j] == -1) {
            i = j;
            do {
                /* first element */
                ref_c = ref;
                flow = TRUE; /* first frame is always a flow frame */
                while (ref_c != NULL && cmp[i].prta_id != ref_c->pid && (flow || ref_c->flow == FALSE)) {
                    ref_c = ref_c->pfp;
                    flow = FALSE;
                }
                if (ref_c == NULL || (!flow && ref_c->flow == TRUE)) {
                    return -1;
                }
                /* second element */
                eval_c = eval;
                flow = TRUE; /* first frame is always a flow frame */
                while (eval_c != NULL && cmp[i].prtb_id != eval_c->pid && (flow || eval_c->flow == FALSE)) {
                    eval_c = eval_c->pfp;
                    flow = FALSE;
                }
                if (eval_c == NULL || (!flow && eval_c->flow == TRUE)) {
                    return -1;
                }
                /* compare */
                res = 0;

                if (FTCmp(&ref_c->attr[cmp[i].atta_id], &eval_c->attr[cmp[i].attb_id], cmp[i].type, cmp[i].op, NULL) == 0)
                    res = 1;

                bres[i] = res;
                i = cmp[i].simil;
            } while (i != -1);
        }
        j++;
    } while (j<ncmp);

    /* boolean */
    for (j=0; j<nbln; j++) {
        if (bln[j].op) {
            /* or */
            if (bres[bln[j].a] || bres[bln[j].b])
                bres[ncmp+j] = 1;
            else
                bres[ncmp+j] = 0;
        }
        else {
            /* and */
            if (bres[bln[j].a] && bres[bln[j].b])
                bres[ncmp+j] = 1;
            else
                bres[ncmp+j] = 0;
        }
    }

    return bres[nrules-1];
}


unsigned long RuleStkHash(const flow_rule *rules, int rule_num, const pstack_f *stk)
{
    unsigned long hash, tmp;
    const pstack_f *frame;
    ftval val;
    int i, j;

#ifdef XPL_CHECK_CODE
    if (stk == NULL) {
        LogPrintf(LV_OOPS, "bug in function %s line: %d", __FILE__, __LINE__);
        exit(-1);
    }
#  if CHECK_SINGLE_RULE
    if (rule_num != 1) {
        LogPrintf(LV_OOPS, "bug in function %s line: %d", __FILE__, __LINE__);
        exit(-1);
    }
#  endif
#endif

    hash = 0;
    for (i=0; i<rule_num; i++) {
        for (j=0; j<rules[i].ncmp; j++) {
            frame = ProtStackSearchProt(stk, rules[i].cmp[j].prta_id);
            if (frame != NULL) {
                ProtGetAttr(frame, rules[i].cmp[j].atta_id, &val);
                tmp = FTHash(&val, rules[i].cmp[j].type);
                hash += tmp;
                /*LogPrintf(LV_DEBUG, "hash a: %i %i %lu", rules[i].cmp[j].prta_id, rules[i].cmp[j].type, tmp);*/
            }
            frame = ProtStackSearchProt(stk, rules[i].cmp[j].prtb_id);
            if (frame != NULL) {
                ProtGetAttr(frame, rules[i].cmp[j].attb_id, &val);
                tmp = FTHash(&val, rules[i].cmp[j].type);
                hash += tmp;
                /*LogPrintf(LV_DEBUG, "hash b: %i %i %lu", rules[i].cmp[j].prtb_id, rules[i].cmp[j].type, tmp);*/
            }
        }
    }
    /*LogPrintf(LV_DEBUG, "hash: %lu", hash);*/

    return hash;
}


bool RuleSort(const flow_rule *rules, int rule_num)
{
    bool ret = TRUE;
    int i;

    for (i=0; i<rule_num; i++) {
        if (rules[i].cmp_eq != TRUE) {
            ret = FALSE;
            break;
        }
    }

    return ret;
}


unsigned short RuleStkMetric(flow_rule *rule, const pstack_f *stk)
{
    int i, j, t;
    const pstack_f *nxt;
    unsigned short metric;
    
    if (rule->ncmp == 0) {
        /* disable rule */
        return USHRT_MAX;
    }

    metric = 0;
    for (i=0; i!=rule->ncmp; i++) {
        nxt = stk;
        t = 0;
        while (nxt != NULL && rule->cmp[i].prta_id != nxt->pid) {
            t++;
            nxt = nxt->pfp;
        }
        if (nxt != NULL) {
            metric += t;
        }
        else
            return USHRT_MAX;
    }

    return metric;
}



