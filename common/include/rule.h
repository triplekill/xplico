/* rule.h
 * data type, function converter and verification
 *
 * $Id: rule.h,v 1.4 2007/09/08 08:17:01 costa Exp $
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


#ifndef __RULE_H__
#define __RULE_H__


#include "ftypes.h"
#include "packet.h"


/** rule flow */
typedef struct _cmp_r cmp_r;
struct _cmp_r {
    enum ftype type; /**< compare data type */
    enum ft_op op;   /**< compare operand */
    int prta_id;     /**< protocol A ID */
    int atta_id;     /**< attribiut ID (in the stack) of protocl A */
    int prtb_id;     /**< protocol B ID */
    int attb_id;     /**< attribiut ID (in the stack) of protocl B */
    int simil;       /**< next cmp with same prta_id prtb_id */
};


typedef struct _bln_r bln_r;
struct _bln_r {
    short op;      /**< operation type 0=AND, 1=OR */
    short a;       /**< element A */
    short b;       /**< element B */
};


typedef struct _flow_rule flow_rule;
struct _flow_rule {
    char *rule;   /**< rule */
    cmp_r *cmp;   /**< element to compare */
    int ncmp;     /**< number of compare */
    bool cmp_eq;  /**< true if all campare have equal operand */
    bln_r *bln;   /**< boolean rules */
    int nbln;     /**< number of boolean rules */
    int *bres;    /**< boolean result  */
    int nrules;   /**< nbln + ncmp */
};


int RuleConvert(flow_rule *rule);
int RuleCheck(flow_rule *rule, const pstack_f *ref, const pstack_f *eval);
unsigned long RuleStkHash(const flow_rule *rules, int rule_num, const pstack_f *pkt);
bool RuleSort(const flow_rule *rules, int rule_num);
unsigned short RuleStkMetric(flow_rule *rule, const pstack_f *stk);

#endif /* __RULE_H__ */
