/*******************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * The Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Simon Bernard - initial API and implementation
 *
 *******************************************************************************/
/*
 Copyright (c) 2016 Intel Corporation

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 THE POSSIBILITY OF SUCH DAMAGE.
*/
#include "internals.h"
#include "liblwm2m.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// the maximum payload transferred by block1 we accumulate per resource and server
#ifndef MAX_BLOCK1_SIZE
#define MAX_BLOCK1_SIZE 4096
#endif

#define ADD_TO_HANDLER_LIST(head,node) (lwm2m_block1_write_handler*)LWM2M_INTERNAL_LIST_ADD(head,node)
#define RM_FROM_HANDLER_LIST(head,node) (lwm2m_block1_write_handler*)LWM2M_INTERNAL_LIST_RM(head,node)
#define FIND_FROM_HANDLER_LIST_DM_URI(head,uri) (lwm2m_block1_write_handler*)LWM2M_INTERNAL_LIST_FIND(head,getResourceHandlerPred,uri)
#define FIND_FROM_HANDER_LIST_STR_URI(head,uri) (lwm2m_block1_write_handler*)LWM2M_INTERNAL_LIST_FIND(head,getUriHandlerPred,uri)
#define ADD_TO_PEER_LIST(head,node) (lwm2m_block1_peer_list *)LWM2M_INTERNAL_LIST_ADD(head,node)
#define RM_FROM_PEER_LIST(head,node) (lwm2m_block1_peer_list *)LWM2M_INTERNAL_LIST_RM(head,node)
#define FIND_FROM_PEER_LIST(head,peer) (lwm2m_block1_peer_list *)LWM2M_INTERNAL_LIST_FIND(head,getPeerDataPred,peer)


static uint8_t getResourceHandlerPred(lwm2m_internal_list_t * node, void* uriV){
    lwm2m_block1_write_handler * handler = (lwm2m_block1_write_handler *)node;
    lwm2m_uri_t * uri = (lwm2m_uri_t*)uriV;
    lwm2m_uri_t uriHandler;
    if(lwm2m_stringToUri(handler->uri,strlen(handler->uri),&uriHandler) > 0){
        if(uri->objectId == uriHandler.objectId && uri->instanceId == uriHandler.instanceId && uri->resourceId == uriHandler.resourceId){
            return 1;
        }
    }
    return 0;
}

static uint8_t getPeerDataPred(lwm2m_internal_list_t * node, void * peer){
    lwm2m_block1_peer_list * peerListP = (lwm2m_block1_peer_list *)node;
    if(peerListP->peer == peer) {
        return 1;
    }
    return 0;
}

static uint8_t getUriHandlerPred(lwm2m_internal_list_t * node, void * uriV){
    lwm2m_block1_write_handler * handler = (lwm2m_block1_write_handler *)node;
    char * uri = (char*)uriV;
    if(strcmp(handler->uri,uri) == 0) return 1;
    return 0;
}

typedef struct _block1_data_list_t{
    struct _block1_data_list_t * next;
    void * peer;
    uint8_t * buffer;
    size_t bufferLen;
} block1_data_list_t;

typedef struct _block1_data_t{
    block1_data_list_t * list;
}block1_data_t;

#define ADD_TO_DATA_LIST(head,node) (block1_data_list_t *)LWM2M_INTERNAL_LIST_ADD(head,node)
#define RM_FROM_DATA_LIST(head,node) (block1_data_list_t*)LWM2M_INTERNAL_LIST_RM(head,node)
#define FIND_FROM_DATA_LIST_PEER(head,peer) (block1_data_list_t*)LWM2M_INTERNAL_LIST_FIND(head,getPeerFromListPred,peer)

static uint8_t getPeerFromListPred(lwm2m_internal_list_t * node, void * peer) {
    block1_data_list_t * block1P = (block1_data_list_t*)node;
    if(block1P->peer == peer) return 1;
    return 0;
}

static uint8_t default_coap_block1_handler(void * peer, uint8_t blockMore, uint8_t * * buffer, size_t * size, void * userData)
{
    block1_data_t * block1DataList = (block1_data_t*)userData;
    block1_data_list_t * block1DataP = FIND_FROM_DATA_LIST_PEER(block1DataList->list,peer);
    if(block1DataP == NULL){
        block1DataP = lwm2m_malloc(sizeof(block1_data_list_t));
        if(block1DataP == NULL) return COAP_500_INTERNAL_SERVER_ERROR;
        memset(block1DataP,0,sizeof(block1_data_list_t));
        block1DataP->peer = peer;
        block1DataList->list = ADD_TO_DATA_LIST(block1DataList->list,block1DataP);
    }
    //error or timeout occured
    if(buffer == NULL){
        block1DataList->list = RM_FROM_DATA_LIST(block1DataList->list,block1DataP);
        if(block1DataP->buffer != NULL) lwm2m_free(block1DataP->buffer);
        lwm2m_free(block1DataP);
        return COAP_NO_ERROR;
    }

    if(block1DataP->bufferLen + *size > MAX_BLOCK1_SIZE) {
        if(block1DataP->buffer != NULL) lwm2m_free(block1DataP->buffer);
        block1DataList->list = RM_FROM_DATA_LIST(block1DataList->list,block1DataP);
        lwm2m_free(block1DataP);
        return COAP_413_ENTITY_TOO_LARGE;
    }

    uint8_t * buf = lwm2m_malloc(block1DataP->bufferLen + *size);
    if(buf == NULL) {
        if(block1DataP->buffer != NULL) lwm2m_free(block1DataP->buffer);
        block1DataList->list = RM_FROM_DATA_LIST(block1DataList->list,block1DataP);
        lwm2m_free(block1DataP);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }
    if(block1DataP->bufferLen > 0){
        memcpy(buf,block1DataP->buffer,block1DataP->bufferLen);
    }
    memcpy(buf+block1DataP->bufferLen,*buffer,*size);
    if(block1DataP->buffer != NULL) {
        lwm2m_free(block1DataP->buffer);
        block1DataP->buffer = buf;
    }
    block1DataP->bufferLen += *size;

    if(blockMore){
        *buffer = NULL;
        *size = 0;
    }
    else {
        block1DataList->list = RM_FROM_DATA_LIST(block1DataList->list,block1DataP);
        *buffer = block1DataP->buffer;
        *size = block1DataP->bufferLen;
        lwm2m_free(block1DataP);
    }
    return COAP_NO_ERROR;
}

static lwm2m_block1_write_handler * createDefaultHandler(char * uri) {
    lwm2m_block1_write_handler * handler = (lwm2m_block1_write_handler *)lwm2m_malloc(sizeof(lwm2m_block1_write_handler));
    if(handler == NULL) return NULL;
    memset(handler,0,sizeof(lwm2m_block1_write_handler));
    handler->uri = lwm2m_strdup(uri);
    if(handler->uri == NULL){
        lwm2m_free(handler);
        return NULL;
    }
    handler->userData = lwm2m_malloc(sizeof(block1_data_t));
    if(handler->userData == NULL) {
        lwm2m_free(handler->uri);
        lwm2m_free(handler);
        return NULL;
    }
    memset(handler->userData,0,sizeof(block1_data_t));
    handler->callback = default_coap_block1_handler;
    return handler;
}

uint8_t coap_block1_handler(lwm2m_context_t * contextP,
                            void * peer, 
                            char * uriStr,
                            uint16_t mid,
                            uint8_t * buffer,
                            size_t length,
                            uint16_t blockSize,
                            uint32_t blockNum,
                            bool blockMore,
                            uint8_t ** outputBuffer,
                            size_t * outputLength)
{
    lwm2m_block1_write_handler * handler = NULL;
    lwm2m_block1_peer_list * serverData = NULL;
    uint8_t * * bufferP = &buffer;
    size_t * bufferLength = &length;
    lwm2m_uri_t uri;
    uint8_t coap_ret;
    int ret = lwm2m_stringToUri(uriStr,strlen(uriStr),&uri);
    if(ret > 0){
        if(LWM2M_URI_IS_SET_OBJECT(&uri) && LWM2M_URI_IS_SET_INSTANCE(&uri) && LWM2M_URI_IS_SET_RESOURCE(&uri)) {
            handler = FIND_FROM_HANDLER_LIST_DM_URI(contextP->block1HandlerList,&uri);
        }
    }
    if(handler == NULL) {
        //get handler which is not part of lwm2m data managment
        handler = FIND_FROM_HANDER_LIST_STR_URI(contextP->block1HandlerList, uriStr);
    }
    

    if(handler == NULL){
        handler = createDefaultHandler(uriStr);
        if(handler == NULL) return COAP_500_INTERNAL_SERVER_ERROR;
        contextP->block1HandlerList = ADD_TO_HANDLER_LIST(contextP->block1HandlerList,handler);
    }
    serverData = FIND_FROM_PEER_LIST(handler->peerList,peer);
    //manage new block1 transfer
    if(blockNum == 0){
        //we have not already received message of server
        if(serverData == NULL){
            serverData = (lwm2m_block1_peer_list *)lwm2m_malloc(sizeof(lwm2m_block1_peer_list));
            if(serverData == NULL) return COAP_500_INTERNAL_SERVER_ERROR;
            memset(serverData,0,sizeof(lwm2m_block1_peer_list));
            serverData->peer = peer;
            serverData->timeout = lwm2m_gettime() + COAP_EXCHANGE_LIFETIME;
            serverData->lastMid = mid;
            handler->peerList = ADD_TO_PEER_LIST(handler->peerList,serverData);
        }
        //new transmission started without end of last transmission
        else {
            handler->callback(peer,0,0,0,handler->userData);
            handler->peerList = RM_FROM_PEER_LIST(handler->peerList,serverData);
            lwm2m_free(serverData);
            return COAP_408_REQ_ENTITY_INCOMPLETE;
        }
    }
    else {
        //we never received first block
        if(serverData == NULL){
            return COAP_408_REQ_ENTITY_INCOMPLETE;
        }
        //we have already received this message
        if(serverData->lastMid == mid) {
            return NO_ERROR;
        }
        //we did not received messages in correct order
        if(serverData->lastBlockNum + 1 != blockNum){
            return COAP_408_REQ_ENTITY_INCOMPLETE;
        }


        serverData->lastMid = mid;
        serverData->lastBlockNum = blockNum;
        serverData->timeout = lwm2m_gettime() + COAP_EXCHANGE_LIFETIME;
    }

    coap_ret = handler->callback(peer,blockMore,bufferP,bufferLength,handler->userData);
    if(coap_ret == COAP_500_INTERNAL_SERVER_ERROR || coap_ret == COAP_413_ENTITY_TOO_LARGE){
        return coap_ret;
    }

    if (blockMore)
    {
        *outputLength = -1;
        return COAP_231_CONTINUE;
    }
    else
    {
        // buffer is full, set output parameter
        // we don't free it to be able to send retransmission
        serverData->buffer = *bufferP;
        *outputLength = *bufferLength;
        *outputBuffer = *bufferP;
        //should be removed with next step
        serverData->timeout = lwm2m_gettime();

        return NO_ERROR;
    }
}


#ifdef LWM2M_CLIENT_MODE

int lwm2m_add_block1_handler(lwm2m_context_t * contextP, lwm2m_uri_t * uri, lwm2m_block1_write_callback callback, void* userData) {
    uint8_t uriString[URI_MAX_STRING_LEN+1];
    lwm2m_block1_write_handler * handler = NULL;
    if(!LWM2M_URI_IS_SET_OBJECT(uri) || !LWM2M_URI_IS_SET_INSTANCE(uri) || !LWM2M_URI_IS_SET_RESOURCE(uri)) return COAP_500_INTERNAL_SERVER_ERROR;
    if(FIND_FROM_HANDLER_LIST_DM_URI(contextP->block1HandlerList,uri) != NULL) return COAP_500_INTERNAL_SERVER_ERROR;

    handler = lwm2m_malloc(sizeof(lwm2m_block1_write_handler));
    if(handler == NULL) return COAP_500_INTERNAL_SERVER_ERROR;
    memset(handler,0,sizeof(lwm2m_block1_write_handler));
    if(uri_toString(uri,uriString,URI_MAX_STRING_LEN,NULL) <=0 ){
        lwm2m_free(handler);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }
    handler->uri = lwm2m_strdup((char*)uriString);
    if(handler->uri == NULL) {
        lwm2m_free(handler);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }
    handler->callback = callback;
    handler->userData = userData;

    contextP->block1HandlerList = ADD_TO_HANDLER_LIST(contextP->block1HandlerList,handler);

    return COAP_NO_ERROR;
}

#endif

void block1_step(lwm2m_context_t * contextP, time_t currentTime, time_t * timeoutP) {
    //check timeout of server_data, remove default handler if no server are available
    //free buffer of server_data
    lwm2m_block1_write_handler * handler = contextP->block1HandlerList;

    while(handler != NULL) {
        lwm2m_block1_peer_list * peerP = handler->peerList;
        while(peerP != NULL) {
            if(peerP->timeout - currentTime > 0 && peerP->timeout - currentTime < *timeoutP){
                *timeoutP = peerP->timeout - currentTime;
            }
            //received data got invalid, free buffers
            if(peerP->timeout <= currentTime){
                lwm2m_block1_peer_list * toRm = peerP;
                //call with invalid data to clear all buffers
                handler->callback(peerP->peer,0,0,0,handler->userData);
                peerP = peerP->next;
                handler->peerList = RM_FROM_PEER_LIST(handler->peerList,toRm);
                if(toRm->buffer != NULL) lwm2m_free(toRm->buffer);
                lwm2m_free(toRm);
            }
            else {
                peerP = peerP->next;
            }
        }

        //if there is no receiving ongoing and default handler is set, remove it to save RAM
        if(handler->peerList == NULL && handler->callback == default_coap_block1_handler) {
            lwm2m_block1_write_handler * toRm = handler;
            handler = handler->next;
            contextP->block1HandlerList = RM_FROM_HANDLER_LIST(contextP->block1HandlerList,toRm);
            lwm2m_free(toRm->uri);
            lwm2m_free(toRm->userData);
            lwm2m_free(toRm);
        }
        else {
            handler = handler->next;
        }
        
    }

}

#ifdef LWM2M_SERVER_MODE

typedef struct
{
    uint16_t clientID;
    uint16_t lastChunkNum;
    uint32_t bytesSent;
    uint32_t completeSize;
    lwm2m_blockwise_buffer_callback callback;
    void * userData;
    lwm2m_uri_t uri;
} blockwise_data_t;

static void prv_resultCallback(lwm2m_context_t * contextP,
                               lwm2m_transaction_t * transacP,
                               void * message);


static int createBlockWiseTransaction(lwm2m_context_t * contextP,
                                        lwm2m_client_t * clientP,
                                        lwm2m_uri_t * uriP,
                                        uint32_t completeSize,
                                        uint16_t chunkSize,
                                        uint32_t bytesSent,
                                        uint32_t chunkNum,
                                        lwm2m_blockwise_buffer_callback callback,
                                        void * userData)
{
    
    lwm2m_transaction_t * transaction;
    uint8_t * chunk;
    uint16_t currentChunkSize;
    uint8_t more;
    blockwise_data_t * data;
    int ret;

    if(callback == NULL){
        return COAP_404_NOT_FOUND;
    }

    chunk = lwm2m_malloc(chunkSize);
    if(chunk == NULL){
        return COAP_500_INTERNAL_SERVER_ERROR;
    }
    ret = callback(bytesSent,chunk,chunkSize,userData);
    if(ret <= 0) {
        lwm2m_free(chunk);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }
    currentChunkSize = ret;

    if(bytesSent + currentChunkSize < completeSize) more = 1;

    transaction = transaction_new(clientP->sessionH, COAP_POST, clientP->altPath, uriP, contextP->nextMID++, 4, NULL);
    if (transaction == NULL) 
    {
        lwm2m_free(chunk);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    ret = coap_set_header_block1(transaction->message, chunkNum, more, chunkSize);
    if(ret == 0)
    {
        lwm2m_free(chunk);
        lwm2m_free(transaction);
        return COAP_406_NOT_ACCEPTABLE;
    }

    

    data = (blockwise_data_t *)lwm2m_malloc(sizeof(blockwise_data_t));
    if(data == NULL)
    {
        lwm2m_free(chunk);
        lwm2m_free(transaction);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }
    data->bytesSent = bytesSent + currentChunkSize;
    data->lastChunkNum = chunkNum;
    data->clientID = clientP->internalID;
    data->completeSize = completeSize;
    data->callback = callback;
    data->userData = userData;
    memcpy(&data->uri,uriP,sizeof(lwm2m_uri_t));

    transaction->userData = data;
    transaction->callback = prv_resultCallback;

    coap_set_payload(transaction->message, chunk, currentChunkSize);

    contextP->transactionList = (lwm2m_transaction_t *)LWM2M_LIST_ADD(contextP->transactionList, transaction);

    ret = transaction_send(contextP, transaction);
    lwm2m_free(chunk);
    if(ret != 0){
        lwm2m_free(data);
    }
    return ret;
}


void prv_resultCallback(lwm2m_context_t * contextP,
                        lwm2m_transaction_t * transacP,
                        void * message)
{
    blockwise_data_t * dataP = (blockwise_data_t *)transacP->userData;
    uint32_t chunkLength;
    chunkLength = 0;
    

    if(message == NULL){
        //block transfer can be terminated because of error
        dataP->callback(0,0,COAP_500_INTERNAL_SERVER_ERROR,dataP->userData);
    }
    else {
        coap_packet_t * packet = (coap_packet_t *)message;
        if(packet->code == COAP_231_CONTINUE) {
            uint16_t block1_size;
            coap_get_header_block1(packet, NULL, NULL, &block1_size, NULL);
            chunkLength = MIN(block1_size,REST_MAX_CHUNK_SIZE);
        }
        else if(packet->code == COAP_204_CHANGED) {
            //block transfer can be terminated
            dataP->callback(dataP->bytesSent,0,0,dataP->userData);
        }
        else {
            //block transfer can be terminated because of error
            dataP->callback(0,0,packet->code,dataP->userData);
        }
    }
    
    if(chunkLength != 0){
        lwm2m_client_t * clientP;
        clientP = (lwm2m_client_t *)lwm2m_list_find((lwm2m_list_t *)contextP->clientList, dataP->clientID);
        if(clientP == NULL)
        {
            dataP->callback(0,0,COAP_404_NOT_FOUND,dataP->userData);
            return;
        }
        createBlockWiseTransaction( contextP,clientP, &dataP->uri,
                                    dataP->completeSize,
                                    chunkLength,dataP->bytesSent,
                                    dataP->lastChunkNum + 1,
                                    dataP->callback, dataP->userData);
    }
    lwm2m_free(dataP);
}


int lwm2m_dm_write_block1(lwm2m_context_t * contextP, 
                         uint16_t clientID,
                         lwm2m_uri_t * uriP,
                         uint32_t completeSize,
                         lwm2m_blockwise_buffer_callback callback, 
                         void * userData)
{
    lwm2m_client_t * clientP;
    clientP = (lwm2m_client_t *)lwm2m_list_find((lwm2m_list_t *)contextP->clientList, clientID);
    if (clientP == NULL) return COAP_404_NOT_FOUND;
    return createBlockWiseTransaction(contextP,clientP,uriP,completeSize,REST_MAX_CHUNK_SIZE,0,0,callback,userData);
}

#endif