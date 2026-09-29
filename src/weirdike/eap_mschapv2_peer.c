/*
 * WeirdIKE -- eap_mschapv2_peer.c : client-side EAP-MSCHAPv2 method state machine.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "eap_mschapv2_peer.h"
#include "eap_mschapv2_crypto.h"
#include "ike_eap.h"
#include <string.h>

static void wipe(void *p, size_t n) {
    volatile uint8_t *v=(volatile uint8_t*)p;
    while(n--) *v++=0;
}
static int ct_equal(const uint8_t *a,const uint8_t *b,size_t n) {
    uint8_t d=0; for(size_t i=0;i<n;i++) d|=(uint8_t)(a[i]^b[i]); return d==0;
}
static void fail_peer(eap_mschapv2_peer_t *p) {
    if (!p) return;
    /* A failed method never continues: drop EVERY secret now (password, challenges, NT-Response,
     * expected authenticator response, MSK, cached packets), not only the MSK. */
    wipe(p->password,sizeof(p->password)); p->password_len=0;
    wipe(p->authenticator_challenge,sizeof(p->authenticator_challenge));
    wipe(p->peer_challenge,sizeof(p->peer_challenge));
    wipe(p->nt_response,sizeof(p->nt_response));
    wipe(p->expected_authenticator_response,sizeof(p->expected_authenticator_response));
    wipe(p->last_request,sizeof(p->last_request)); p->last_request_len=0;
    wipe(p->last_response,sizeof(p->last_response)); p->last_response_len=0; p->have_last_request=0;
    wipe(p->msk,sizeof(p->msk)); p->have_method_keys=0; p->state=EAP_PEER_FAILED;
}
static void account_part(const uint8_t *id,size_t id_len,const uint8_t **user,size_t *user_len) {
    *user=id; *user_len=id_len;
    for(size_t i=0;i<id_len;i++) if(id[i]=='\\') { *user=id+i+1; *user_len=id_len-i-1; return; }
}
static int cache_response(eap_mschapv2_peer_t *p,const uint8_t *req,size_t req_len,const uint8_t *resp,size_t resp_len) {
    if(req_len>EAP_MSCHAPV2_MAX_PACKET||resp_len>EAP_MSCHAPV2_MAX_PACKET)return -1;
    memcpy(p->last_request,req,req_len); p->last_request_len=req_len;
    if(resp_len)memcpy(p->last_response,resp,resp_len);
    p->last_response_len=resp_len;
    p->have_last_request=1; return 0;
}

int eap_mschapv2_peer_init(eap_mschapv2_peer_t *p,const weirdike_crypto_t *crypto,
                           const uint8_t *identity,size_t identity_len,
                           const uint8_t *password,size_t password_len) {
    if(!p||!crypto||!crypto->random||!crypto->sha1||identity_len==0||identity_len>EAP_MSCHAPV2_MAX_IDENTITY||
       password_len>EAP_MSCHAPV2_MAX_PASSWORD||!identity||(password_len&&!password)) return -1;
    memset(p,0,sizeof(*p)); p->crypto=crypto;
    memcpy(p->identity,identity,identity_len);p->identity_len=identity_len;
    if(password_len)memcpy(p->password,password,password_len);
    p->password_len=password_len;
    p->state=EAP_PEER_WAIT_REQUEST; return 0;
}

int eap_mschapv2_peer_process(eap_mschapv2_peer_t *p,const uint8_t *request,size_t request_len,
                              uint8_t *response,size_t response_cap,size_t *response_len) {
    if(!p||!request||!response_len||p->state==EAP_PEER_FAILED||p->state==EAP_PEER_COMPLETE)return -1;
    *response_len=0;
    if(p->have_last_request&&request_len==p->last_request_len&&memcmp(request,p->last_request,request_len)==0) {
        if(p->last_response_len>response_cap||(!response&&p->last_response_len))return -1;
        if(p->last_response_len)memcpy(response,p->last_response,p->last_response_len);
        *response_len=p->last_response_len; return 0;
    }

    eap_packet_t ep;
    if(eap_parse(request,request_len,&ep)!=0){fail_peer(p);return -1;}
    if(ep.code==EAP_CODE_FAILURE){fail_peer(p);return -1;}
    if(ep.code==EAP_CODE_SUCCESS) {
        if(p->state!=EAP_PEER_WAIT_OUTER_RESULT||!p->have_method_keys){fail_peer(p);return -1;}
        p->state=EAP_PEER_COMPLETE; return 0;
    }
    if(ep.code!=EAP_CODE_REQUEST){fail_peer(p);return -1;}

    if(ep.type==EAP_TYPE_IDENTITY) {
        if(p->state!=EAP_PEER_WAIT_REQUEST){fail_peer(p);return -1;}
        if(!response){fail_peer(p);return -1;}
        if(eap_build_identity_response(ep.identifier,p->identity,p->identity_len,response,response_cap,response_len)!=0){fail_peer(p);return -1;}
        if(cache_response(p,request,request_len,response,*response_len)!=0){fail_peer(p);return -1;}
        return 0;
    }

    if(ep.type!=EAP_TYPE_MSCHAPV2){fail_peer(p);return -1;}
    if(eap_mschapv2_is_failure(request,request_len)>0){fail_peer(p);return -1;}

    eap_mschapv2_challenge_t ch;
    if(eap_mschapv2_parse_challenge(request,request_len,&ch)==0) {
        if(p->state!=EAP_PEER_WAIT_REQUEST||!response){fail_peer(p);return -1;}
        memcpy(p->authenticator_challenge,ch.authenticator_challenge,16);
        if(p->crypto->random(p->crypto->ctx,p->peer_challenge,16)!=0){fail_peer(p);return -1;}
        const uint8_t *user;size_t user_len;account_part(p->identity,p->identity_len,&user,&user_len);
        if(user_len==0||mschapv2_generate_nt_response(p->crypto,p->authenticator_challenge,p->peer_challenge,
                                                     user,user_len,p->password,p->password_len,p->nt_response)!=0){fail_peer(p);return -1;}
        if(mschapv2_generate_authenticator_response(p->crypto,p->password,p->password_len,p->nt_response,
                                                    p->peer_challenge,p->authenticator_challenge,user,user_len,
                                                    p->expected_authenticator_response)!=0){fail_peer(p);return -1;}
        if(mschapv2_generate_msk(p->crypto,p->password,p->password_len,p->nt_response,p->msk)!=0){fail_peer(p);return -1;}
        p->have_method_keys=1;
        if(eap_mschapv2_build_response(ch.eap_identifier,ch.mschapv2_identifier,p->peer_challenge,p->nt_response,
                                       p->identity,p->identity_len,response,response_cap,response_len)!=0){fail_peer(p);return -1;}
        if(cache_response(p,request,request_len,response,*response_len)!=0){fail_peer(p);return -1;}
        p->state=EAP_PEER_WAIT_METHOD_RESULT; return 0;
    }

    eap_mschapv2_success_t su;
    if(eap_mschapv2_parse_success(request,request_len,&su)==0) {
        if(p->state!=EAP_PEER_WAIT_METHOD_RESULT||!p->have_method_keys||!response||response_cap<6){fail_peer(p);return -1;}
        if(!ct_equal(su.authenticator_response,p->expected_authenticator_response,20)){fail_peer(p);return -1;}
        if(eap_mschapv2_build_success_response(su.eap_identifier,response,response_len)!=0){fail_peer(p);return -1;}
        if(cache_response(p,request,request_len,response,*response_len)!=0){fail_peer(p);return -1;}
        p->state=EAP_PEER_WAIT_OUTER_RESULT; return 0;
    }

    fail_peer(p);return -1;
}

int eap_mschapv2_peer_complete(const eap_mschapv2_peer_t *p){return p&&p->state==EAP_PEER_COMPLETE;}
int eap_mschapv2_peer_get_msk(const eap_mschapv2_peer_t *p,uint8_t out[64]) {
    if(!p||!out||p->state!=EAP_PEER_COMPLETE||!p->have_method_keys)return -1;
    memcpy(out,p->msk,64);return 0;
}
void eap_mschapv2_peer_deinit(eap_mschapv2_peer_t *p){if(!p)return;wipe(p,sizeof(*p));}
