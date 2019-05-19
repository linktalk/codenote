/*
 * Copyright 2009, 2019 Xuelei Fan
 */
#include <stdio.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>

extern void dump_info();

int main(int argc, char **argv) {
    CK_RV               rv;
    CK_MECHANISM        mechanism = {CKM_RC4, NULL_PTR, 0L};
    CK_SESSION_HANDLE   hSession;

    // initialize teh crypto library
    rv = C_Initialize(NULL_PTR);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_Initialize: Error = 0x%.8X\n", rv);
        return -1;
    }

    dump_info();

    rv = C_Finalize(NULL_PTR);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_Finalize: Error = 0x%.8X\n", rv);
        return -1;
    }

}

void dump_info() {
    CK_RV               rv;
    CK_SLOT_INFO        slotInfo;
    CK_TOKEN_INFO       tokenInfo;
    CK_ULONG            ulSlotCount = 0;
    CK_SLOT_ID_PTR      pSlotList = NULL_PTR;
    int                 i = 0;

    rv = C_GetSlotList(0, NULL_PTR, &ulSlotCount);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_GetSlotList: Error = 0x%.8X\n", rv);
        return;
    }

    fprintf(stdout, "slotCount = %d\n", ulSlotCount);
    pSlotList = malloc(ulSlotCount * sizeof(CK_SLOT_ID));
    if (pSlotList == NULL) {
        fprintf(stderr, "System error: unable to allocate memory");
        return;
    }

    rv = C_GetSlotList(0, pSlotList, &ulSlotCount);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_GetSlotList: Error = 0x%.8X\n", rv);
        free(pSlotList);
        return;
    }

    for (i = 0; i < ulSlotCount; i++) {
        fprintf(stdout, "slot found: %d ----\n", pSlotList[i]);
        rv = C_GetSlotInfo(pSlotList[i], &slotInfo);
        if (rv != CKR_OK) {
            fprintf(stderr, "C_GetSlotInfo: Error = 0x%.8X\n", rv);
            free(pSlotList);
            return;
        }

        fprintf(stdout, "slot description: %s\n", slotInfo.slotDescription);
        fprintf(stdout, "slot manufacturer: %s\n", slotInfo.manufacturerID);
        fprintf(stdout, "slot flags: 0x%.8X\n", slotInfo.flags);
        fprintf(stdout, "slot hardwareVersion: %d.%d\n",
            slotInfo.hardwareVersion.major, slotInfo.hardwareVersion.minor);
        fprintf(stdout, "slot firmwareVersion: %d.%d\n",
            slotInfo.firmwareVersion.major, slotInfo.firmwareVersion.minor);

        rv = C_GetTokenInfo(pSlotList[i], &tokenInfo);
        if (rv != CKR_OK) {
            fprintf(stderr, "C_GetTokenInfo: Error = 0x%.8X\n", rv);
            free(pSlotList);
            return;
        }

        fprintf(stdout, "Token label: %s\n", tokenInfo.label);
        fprintf(stdout, "Token manufacturer: %s\n", tokenInfo.manufacturerID);
        fprintf(stdout, "Token model: %s\n", tokenInfo.model);
        fprintf(stdout, "Token serial: %s\n", tokenInfo.serialNumber);
        fprintf(stdout, "Token flags: 0x%.8X\n", tokenInfo.flags);
        fprintf(stdout, "Token ulMaxSessionCount: %ld\n",
                                tokenInfo.ulMaxSessionCount);
        fprintf(stdout, "Token ulSessionCount: %ld\n",
                                tokenInfo.ulSessionCount);
        fprintf(stdout, "Token ulMaxRwSessionCount: %ld\n",
                                tokenInfo.ulMaxRwSessionCount);
        fprintf(stdout, "Token ulRwSessionCount: %ld\n",
                                tokenInfo.ulRwSessionCount);
        fprintf(stdout, "Token ulMaxPinLen: %ld\n", tokenInfo.ulMaxPinLen);
        fprintf(stdout, "Token ulMinPinLen: %ld\n", tokenInfo.ulMinPinLen);
        fprintf(stdout, "Token ulTotalPublicMemory: %ld\n",
                                tokenInfo.ulTotalPublicMemory);
        fprintf(stdout, "Token ulFreePublicMemory: %ld\n",
                                tokenInfo.ulFreePublicMemory);
        fprintf(stdout, "Token ulTotalPrivateMemory: %ld\n",
                                tokenInfo.ulTotalPrivateMemory);
        fprintf(stdout, "Token ulFreePrivateMemory: %ld\n",
                                tokenInfo.ulFreePrivateMemory);
        fprintf(stdout, "slot hardwareVersion: %d.%d\n",
            tokenInfo.hardwareVersion.major, tokenInfo.hardwareVersion.minor);
        fprintf(stdout, "slot firmwareVersion: %d.%d\n",
            tokenInfo.firmwareVersion.major, tokenInfo.firmwareVersion.minor);
        fprintf(stdout, "Token utcTime: %s\n", tokenInfo.utcTime);
        fprintf(stdout, "\n");
    }

    free(pSlotList);
}

