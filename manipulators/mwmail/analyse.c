/* analyse.c
 * analyse stack and time to realise pei
 *
 * $Id:  $
 *
 * Xplico System
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2011 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "log.h"
#include "analyse.h"
#include "proto.h"
#include "dmemory.h"
#include "pei.h"
#include "fileformat.h"

/* http id */
static int http_id;
static int http_encoding_id;
/* webamil */
static int prot_id;
static int pei_service_id;
static int pei_url_id;
static int pei_client_id;
static int pei_host_id;
static int pei_req_header_id;
static int pei_req_body_id;
static int pei_res_header_id;
static int pei_res_body_id;
static int pei_serv_id;
static int pei_dir_id;
static int pei_to_id;
static int pei_from_id;
static int pei_cc_id;
static int pei_sent_id;
static int pei_rec_id;
static int pei_messageid_id;
static int pei_subj_id;
static int pei_eml_id;
static int pei_html_id;
static int pei_txt_id;

/* webmail variables */
static volatile unsigned short inc;


static pei *WMail2Pei(const char *filename, const pei *mpei, char *dir)
{
    char line[LINE_MAX_SIZE];
    pei *new;
    FILE *fp;
    bool ret;
    int res;
    pei_component *cmpn;

    new = NULL;
    ret = FALSE;
    fp = fopen(filename, "r");
    if (fp != NULL) {
        /* create a PEI */
        PeiNew(&new, prot_id);
        PeiCapTime(new, mpei->time_cap);
        PeiMarker(new, mpei->serial);
        PeiStackFlow(new, mpei->stack);
        /* component */
        //LogPrintf(LV_DEBUG, "Info file: %s", filename);
        while (fgets(line, LINE_MAX_SIZE, fp) != NULL) {
            line[LINE_MAX_SIZE-1] = '\0';
            /* subject */
            res = strncmp(line, WMAIL_FLD_SUBJECT, WMAIL_FLD_SUBJECT_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_subj_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddStingBuff(cmpn, line+WMAIL_FLD_SUBJECT_DIM);
                PeiAddComponent(new, cmpn);
                ret = TRUE;
                continue;
            }
            res = strncmp(line, WMAIL_FLD_FROM, WMAIL_FLD_FROM_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_from_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddStingBuff(cmpn, line+WMAIL_FLD_FROM_DIM);
                PeiAddComponent(new, cmpn);
                ret = TRUE;
                continue;
            }
            res = strncmp(line, WMAIL_FLD_TO, WMAIL_FLD_TO_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_to_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddStingBuff(cmpn, line+WMAIL_FLD_TO_DIM);
                PeiAddComponent(new, cmpn);
                ret = TRUE;
                continue;
            }
            res = strncmp(line, WMAIL_FLD_CC, WMAIL_FLD_CC_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_cc_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddStingBuff(cmpn, line+WMAIL_FLD_CC_DIM);
                PeiAddComponent(new, cmpn);
                continue;
            }
            res = strncmp(line, WMAIL_FLD_MESSAGEID, WMAIL_FLD_MESSAGEID_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_messageid_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddStingBuff(cmpn, line+WMAIL_FLD_MESSAGEID_DIM);
                PeiAddComponent(new, cmpn);
                continue;
            }
            res = strncmp(line, WMAIL_FLD_RECEIVED, WMAIL_FLD_RECEIVED_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_rec_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddStingBuff(cmpn, line+WMAIL_FLD_RECEIVED_DIM);
                PeiAddComponent(new, cmpn);
                continue;
            }
            res = strncmp(line, WMAIL_FLD_SENT, WMAIL_FLD_SENT_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_sent_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddStingBuff(cmpn, line+WMAIL_FLD_SENT_DIM);
                PeiAddComponent(new, cmpn);
                continue;
            }
            res = strncmp(line, WMAIL_FLD_HTML, WMAIL_FLD_HTML_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_html_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddFile(cmpn, "mail.html", strchr(line, ':')+1, 0);
                PeiAddComponent(new, cmpn);
                continue;
            }
            res = strncmp(line, WMAIL_FLD_TXT, WMAIL_FLD_TXT_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_txt_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddFile(cmpn, "mail.txt", strchr(line, ':')+1, 0);
                PeiAddComponent(new, cmpn);
                continue;
            }
            res = strncmp(line, WMAIL_FLD_EML, WMAIL_FLD_EML_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_eml_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddFile(cmpn, "mail.eml", line+WMAIL_FLD_EML_DIM, 0);
                PeiAddComponent(new, cmpn);
                continue;
            }
            res = strncmp(line, WMAIL_FLD_FILENAME, WMAIL_FLD_FILENAME_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                LogPrintfPei(LV_WARNING, mpei, "Attached filename: %s", line+WMAIL_FLD_FILENAME_DIM);
                continue;
            }
        }
        fclose(fp);
        remove(filename);
    }
    if (ret == FALSE) {
        PeiFree(new);
        new = NULL;
    }
    else {
        /* dir */
        PeiNewComponent(&cmpn, pei_dir_id);
        PeiCompCapTime(cmpn, mpei->time_cap);
        PeiCompAddStingBuff(cmpn, dir);
        PeiAddComponent(new, cmpn);
    }

    return new;
}


static pei *WMYahoo(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    struct stat finfo;

    resp[0] = '\0';

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_dir_id) {
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    
    /* sent or received */
    if (rqb == NULL && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/yahoo_%lu_%p_%i", ProtTmpDir(), time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_yahoo.pyc %s %s", new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_yahoo.pyc %s %s", rsb, resp);
        }

        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo python (wbm_yahoo.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo python (wbm_yahoo.pyc) error: %s", rsb);
        }
    }
    else if (rqb != NULL) {
        /* sent */
        /* extract all information:
           from, to, cc, bcc, subject, email */
        sprintf(resp, "%s/yahoo_%lu_%p_%i", ProtTmpDir(), time(NULL), rqb, inc++);
        sprintf(cmd, "./wbm_yahoo.pyc -s %s %s", rqb, resp);
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo python (wbm_yahoo.pyc) system error: %s", rqb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo python (wbm_yahoo.pyc) error: %s", rqb);
        }
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "yahoo");
                    PeiAddComponent(new_pei, cmpn);
                    PeiIns(new_pei);
                }
                else {
                    LogPrintfPei(LV_ERROR, ppei, "Yahoo python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}


static pei *WMYahooV2(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    bool out;
    struct stat finfo;

    resp[0] = '\0';
    out = FALSE;

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_dir_id) {
            if (strcmp(cmpn->strbuf, "r") == 0)
                out = FALSE;
            else if (strcmp(cmpn->strbuf, "s") == 0)
                out = TRUE;
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    
    /* sent or received */
    if (!out && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/yahoo_v2_%lu_%p_%i", ProtTmpDir(), time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_yahoo_v2.pyc %s %s", new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_yahoo_v2.pyc %s %s", rsb, resp);
        }

        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo v2 python (wbm_yahoo_v2.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo v2 python (wbm_yahoo_v2.pyc) error: %s", rsb);
        }
    }
    else if (out && rqb != NULL) {
        /* sent */
        /* extract all information:
           from, to, cc, bcc, subject, email */
        sprintf(resp, "%s/yahoo_v2_%lu_%p_%i", ProtTmpDir(), time(NULL), rqb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_yahoo_v2.pyc -s %s %s %s", rqb, new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_yahoo_v2.pyc -s %s %s %s", rqb, rsb, resp);
        }
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo v2 python (wbm_yahoo_v2.pyc) system error: %s %s", rqb, rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo v2 python (wbm_yahoo_v2.pyc) error: %s %s", rqb, rsb);
        }
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "yahoo_v2");
                    PeiAddComponent(new_pei, cmpn);
                    PeiIns(new_pei);
                }
                else {
                    LogPrintfPei(LV_ERROR, ppei, "Yahoo v2 python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}


static pei *WMYahooAndroid(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb;
    char dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    struct stat finfo;
    FILE *fp;

    resp[0] = '\0';

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    dir = 'r';
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
            /* check if sent or not */
            fp = fopen(rqb, "r");
            if (fp != NULL) {
                fread(resp, 1, WMAIL_STR_DIM, fp);
                fclose(fp);
                if (strncmp(resp, "ac=SendMessage&appid=", 21) == 0) {
                    dir = 's';
                }
            }
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    
    /* sent or received */
    if (rqb != NULL && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/yahoo_android_%lu_%p_%i", ProtTmpDir(), time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            if (dir == 'r') {
                sprintf(cmd, "./wbm_yahoo_android.pyc %s %s", new_path, resp);
            }
            else {
                sprintf(cmd, "./wbm_yahoo_android.pyc -s %s %s %s", rqb, new_path, resp);
            }
        }
        else {
            /* not compressed */
            if (dir == 'r') {
                sprintf(cmd, "./wbm_yahoo_android.pyc %s %s", rsb, resp);
            }
            else {
                sprintf(cmd, "./wbm_yahoo_android.pyc -s %s %s %s", rqb, rsb, resp);
            }
        }
        LogPrintf(LV_DEBUG, "%s", cmd);
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo Android python (wbm_yahoo_android.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo Android python (wbm_yahoo_android.pyc) error: %s", rsb);
        }
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, &dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "yahoo android");
                    PeiAddComponent(new_pei, cmpn);
                    //PeiPrint(new_pei);
                    PeiIns(new_pei);
                }
                else {
                    LogPrintfPei(LV_ERROR, ppei, "Yahoo Android python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}


static pei *WMAol(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    struct stat finfo;
    bool out;

    resp[0] = '\0';
    out = FALSE;

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_dir_id) {
            if (strcmp(cmpn->strbuf, "r") == 0)
                out = FALSE;
            else if (strcmp(cmpn->strbuf, "s") == 0)
                out = TRUE;
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }

    /* sent or received */
    if (!out && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/aol_out_%lu_%p_%i", ProtTmpDir(), time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_aol.pyc %s %s", new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_aol.pyc %s %s", rsb, resp);
        }
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "AOL python (wbm_aol.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "AOL python (wbm_aol.pyc) error: %s", rsb);
        }
    }
    else if (out && rqb != NULL) {
        /* sent */
        /* extract all information:
           from, to, cc, bcc, subject, email */
        sprintf(resp, "%s/aol_in_%lu_%p_%i", ProtTmpDir(), time(NULL), rqb, inc++);
        sprintf(cmd, "./wbm_aol.pyc -s %s %s", rqb, resp);
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "AOL python (wbm_aol.pyc) system error: %s", rqb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "AOL python (wbm_aol.pyc) error: %s", rqb);
        }
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "aol");
                    PeiAddComponent(new_pei, cmpn);
                    PeiIns(new_pei);
                }
                else {
                    LogPrintfPei(LV_ERROR, ppei, "AOL python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}


static pei *WMAolV2(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    struct stat finfo;
    bool out;

    resp[0] = '\0';
    out = FALSE;

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_dir_id) {
            if (strcmp(cmpn->strbuf, "r") == 0)
                out = FALSE;
            else if (strcmp(cmpn->strbuf, "s") == 0)
                out = TRUE;
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }

    /* sent or received */
    if (!out && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/aol_v2_out_%lu_%p_%i", ProtTmpDir(), time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_aol_v2.pyc %s %s", new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_aol_v2.pyc %s %s", rsb, resp);
        }
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "AOL v2 python (wbm_aol_v2.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "AOL v2 python (wbm_aol_v2.pyc) error: %s", rsb);
        }
    }
    else if (out && rqb != NULL && rsb != NULL) {
        /* sent */
        /* extract all information:
           from, to, cc, bcc, subject, email */
        sprintf(resp, "%s/aol_v2_in_%lu_%p_%i", ProtTmpDir(), time(NULL), rqb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_aol_v2.pyc -s %s %s %s", rqb, new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_aol_v2.pyc -s %s %s %s", rqb, rsb, resp);
        }

        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "AOL v2 python (wbm_aol_v2.pyc) system error: %s", rqb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "AOL v2 python (wbm_aol_v2.pyc) error: %s", rqb);
        }
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "aol");
                    PeiAddComponent(new_pei, cmpn);
                    PeiIns(new_pei);
                }
                else {
                    LogPrintfPei(LV_ERROR, ppei, "AOL v2 python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}

static pei *WMGmail(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    struct stat finfo;
    bool out;

    resp[0] = '\0';
    out = FALSE;

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_dir_id) {
            if (strcmp(cmpn->strbuf, "r") == 0)
                out = FALSE;
            else if (strcmp(cmpn->strbuf, "s") == 0)
                out = TRUE;
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }

    /* sent or received */
    if (!out && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/gmail_out_%lu_%p_%i", ProtTmpDir(), time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_gmail.pyc %s %s", new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_gmail.pyc %s %s", rsb, resp);
        }
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Gmail python (wbm_gmail.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Gmail python (wbm_gmail.pyc) error: %s", rsb);
        }
    }
    else if (out && rqb != NULL && rsb != NULL) {
        /* sent */
        /* extract all information:
           from, to, cc, bcc, subject, email */
        sprintf(resp, "%s/gmail_in_%lu_%p_%i", ProtTmpDir(), time(NULL), rqb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_gmail.pyc -s %s %s %s %s", rqh, rqb, new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_gmail.pyc -s %s %s %s %s", rqh, rqb, rsb, resp);
        }

        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Gmail python (wbm_gmail.pyc) system error: %s", rqb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Gmail python (wbm_gmail.pyc) error: %s", rqb);
        }
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "gmail");
                    PeiAddComponent(new_pei, cmpn);
                    PeiIns(new_pei);
                }
                else {
                    LogPrintfPei(LV_ERROR, ppei, "Gmail python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}


static pei *WMHotmail(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    struct stat finfo;
    bool out;

    resp[0] = '\0';
    out = FALSE;

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_dir_id) {
            if (strcmp(cmpn->strbuf, "r") == 0)
                out = FALSE;
            else if (strcmp(cmpn->strbuf, "s") == 0)
                out = TRUE;
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    
    /* sent or received */
    if (!out && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/live_%lu_%p_%i", ProtTmpDir(), time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_live.pyc %s %s", new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_live.pyc %s %s", rsb, resp);
        }
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Live python (wbm_live.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Live python (wbm_live.pyc) error: %s", rsb);
        }
    }
    else if (out && rqb != NULL) {
        /* sent */
        /* extract all information:
           from, to, cc, bcc, subject, email */
        sprintf(resp, "%s/live_%lu_%p_%i", ProtTmpDir(), time(NULL), rqb, inc++);
        sprintf(cmd, "./wbm_live.pyc -s %s %s", rqb, resp);
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Live python (wbm_live.pyc) system error: %s", rqb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Live python (wbm_live.pyc) error: %s", rqb);
        }     
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "live");
                    PeiAddComponent(new_pei, cmpn);
                    PeiIns(new_pei);
                }
                else {
                    LogPrintfPei(LV_WARNING, ppei, "Live python Decoding failed");
                    LogPrintf(LV_WARNING, "%s", rsb);
                    LogPrintf(LV_WARNING, "%s", rqb);
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}


int AnalyseInit(void)
{    
    /* initialize */
    
    http_id = ProtId("http");
    if (http_id != -1) {
        http_encoding_id = ProtAttrId(http_id, "http.content_encoding");
    }
      
    prot_id = ProtId("webmail");
    if (prot_id != -1) {
        pei_service_id = ProtPeiComptId(prot_id, "service");
        pei_dir_id = ProtPeiComptId(prot_id, "dir");
        pei_url_id = ProtPeiComptId(prot_id, "url");
        pei_client_id = ProtPeiComptId(prot_id, "client");
        pei_host_id = ProtPeiComptId(prot_id, "host");
        pei_req_header_id = ProtPeiComptId(prot_id, "req.header");
        pei_req_body_id = ProtPeiComptId(prot_id, "req.body");
        pei_res_header_id = ProtPeiComptId(prot_id, "res.header");
        pei_res_body_id = ProtPeiComptId(prot_id, "res.body");
        /* components added */
        pei_serv_id = ProtPeiComptId(prot_id, "serv");
        pei_to_id = ProtPeiComptId(prot_id, "to");
        pei_from_id = ProtPeiComptId(prot_id, "from");
        pei_cc_id = ProtPeiComptId(prot_id, "cc");
        pei_sent_id = ProtPeiComptId(prot_id, "sent");
        pei_rec_id = ProtPeiComptId(prot_id, "rec");
        pei_messageid_id = ProtPeiComptId(prot_id, "id");
        pei_subj_id = ProtPeiComptId(prot_id, "subject");
        pei_eml_id = ProtPeiComptId(prot_id, "eml");
        pei_html_id = ProtPeiComptId(prot_id, "html");
        pei_txt_id = ProtPeiComptId(prot_id, "txt");
    }
    
    return 0;
}


int AnalysePei(pei *ppei)
{
    pei_component *cmpn;
    char *unck;
    pei *npei;
    service type;

    if (ppei == NULL)
        return 0;
    
    if (ppei->ret == TRUE) {
        ProtStackFrmDisp(ppei->stack, TRUE);
        LogPrintfPei(LV_WARNING, ppei, "Pei with return!");
    }
    npei = NULL;
    unck = NULL;
    
    /* identify the servce type */
    type = WMS_NONE;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_service_id) {
            unck = cmpn->strbuf;
            if (strcmp(cmpn->strbuf, WMAIL_SERVICE_GMAIL) == 0) {
                type = WMS_GMAIL;
            }
            if (strcmp(cmpn->strbuf, WMAIL_SERVICE_YAHOO) == 0) {
                type = WMS_YAHOO;
            }
            if (strcmp(cmpn->strbuf, WMAIL_SERVICE_YAHOO_V2) == 0) {
                type = WMS_YAHOO_V2;
            }
            else if (strcmp(cmpn->strbuf, WMAIL_SERVICE_YAHOO_ANDRO) == 0) {
                type = WMS_YAHOO_DRIOD;
            }
            else if (strcmp(cmpn->strbuf, WMAIL_SERVICE_AOL) == 0) {
                type = WMS_AOL;
            }
            else if (strcmp(cmpn->strbuf, WMAIL_SERVICE_AOL_V2) == 0) {
                type = WMS_AOL_V2;
            }
            else if (strcmp(cmpn->strbuf, WMAIL_SERVICE_HOTMAIL) == 0) {
                type = WMS_HOTMAIL;
            }
            break;
        }
    }
    /* extract mail */
    switch (type) {
    case WMS_GMAIL:
        npei = WMGmail(ppei);
        PeiDestroy(ppei);
        break;

    case WMS_YAHOO:
        npei = WMYahoo(ppei);
        PeiDestroy(ppei);
        break;

    case WMS_YAHOO_V2:
        npei = WMYahooV2(ppei);
        PeiDestroy(ppei);
        break;

    case WMS_YAHOO_DRIOD:
        npei = WMYahooAndroid(ppei);
        PeiDestroy(ppei);
        break;

    case WMS_AOL:
        npei = WMAol(ppei);
        PeiDestroy(ppei);
        break;

    case WMS_AOL_V2:
        npei = WMAolV2(ppei);
        PeiDestroy(ppei);
        break;

    case WMS_HOTMAIL:
        npei = WMHotmail(ppei);
        PeiDestroy(ppei);
        break;

    case WMS_NONE:
        LogPrintfPei(LV_WARNING, ppei,"Web mail uncknow: %s", unck);
    }
    
    if (npei != NULL) {
        PeiIns(npei);
    }

    return 0;
}


int AnalyseEnd(void)
{
    return 0;
}

