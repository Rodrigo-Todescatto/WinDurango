#include "pch.h"
#include "AcpHal.h"

#include <basetyps.h>
#include <cstdio>
#include <stdlib.h>
#include "../common/debug.h"

#include "contexts.h"
#include <iostream>

struct SHAPE_CONTEXTS {
    UINT32 numSrcContexts;
    UINT32 numEqCompContexts;
    UINT32 numFiltVolContexts;
    UINT32 numDmaContexts;
    UINT32 numXmaContexts;
    UINT32 numPcmContexts;
    SHAPE_SRC_CONTEXT* srcContextArray;
    SHAPE_EQCOMP_CONTEXT* eqCompContextArray;
    SHAPE_FILTVOL_CONTEXT* filtVolContextArray;
    SHAPE_DMA_CONTEXT* dmaContextArray;
    SHAPE_XMA_CONTEXT* xmaContextArray;
    SHAPE_PCM_CONTEXT* pcmContextArray;
    APU_ADDRESS apuSrcContextArray;
    APU_ADDRESS apuEqCompContextArray;
    APU_ADDRESS apuFiltVolContextArray;
    APU_ADDRESS apuDmaContextArray;
    APU_ADDRESS apuXmaContextArray;
    APU_ADDRESS apuPcmContextArray;
};


HRESULT AcpHalAllocateShapeContexts_X(SHAPE_CONTEXTS* ctx) {
    if (ctx->numSrcContexts > 0)
        ctx->srcContextArray = static_cast<SHAPE_SRC_CONTEXT*>(malloc(sizeof(SHAPE_SRC_CONTEXT) * ctx->numSrcContexts));

    if (ctx->numEqCompContexts > 0)
        ctx->eqCompContextArray = static_cast<SHAPE_EQCOMP_CONTEXT*>(malloc(sizeof(SHAPE_EQCOMP_CONTEXT) * ctx->numEqCompContexts));

    if (ctx->numFiltVolContexts > 0)
        ctx->filtVolContextArray = static_cast<SHAPE_FILTVOL_CONTEXT*>(malloc(sizeof(SHAPE_FILTVOL_CONTEXT) * ctx->numFiltVolContexts));

    if (ctx->numDmaContexts > 0)
        ctx->dmaContextArray = static_cast<SHAPE_DMA_CONTEXT*>(malloc(sizeof(SHAPE_DMA_CONTEXT) * ctx->numDmaContexts));

    if (ctx->numXmaContexts > 0)
        ctx->xmaContextArray = static_cast<SHAPE_XMA_CONTEXT*>(malloc(sizeof(SHAPE_XMA_CONTEXT) * ctx->numXmaContexts));

    if (ctx->numPcmContexts > 0)
        ctx->pcmContextArray = static_cast<SHAPE_PCM_CONTEXT*>(malloc(sizeof(SHAPE_PCM_CONTEXT) * ctx->numPcmContexts));

    printf("[AcpHal] allocated shape contexts\n");
    return E_NOTIMPL;
}

HRESULT AcpHalReleaseShapeContexts_X() {
    DEBUG_PRINT( );
	return E_NOTIMPL;
}

HRESULT AcpHalCreate_X(IAcpHal** acpInterface) {
	printf("[WARNING] AcpHalCreate returns back a nullptr, the game is likely to crash!\n");
	*acpInterface = nullptr;
    return E_NOTIMPL;
}

UINT32 AllocSize;

HRESULT ApuAlloc_X(
         void** virtualAddress,
         APU_ADDRESS* physicalAddress,
         UINT32 sizeInBytes,
         UINT32 alignmentInBytes,
         UINT32 flags
)
{
    DEBUG_PRINT( );
    AllocSize = sizeInBytes;
    std::cout << "ACPHAL::ApuAlloc_X flags: " << flags << std::endl;
  
    _aligned_malloc(sizeInBytes, alignmentInBytes);

    std::cout << "ACPHAL::ApuAlloc_X last error: " << GetLastError( ) << std::endl;

    return S_OK;
}

HRESULT ApuCreateHeap_X(size_t initialSize, size_t maximumSize) {
    DEBUG_PRINT( );
    HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, initialSize, maximumSize);
    return S_OK;
}

HRESULT ApuFree_X(void* virtualAddress) {
    DEBUG_PRINT( );
    VirtualFree(virtualAddress, AllocSize, MEM_RELEASE);
    return S_OK;
}

HRESULT ApuHeapGetState_X(
         ApuHeapState* apuHeapState,
         UINT32 flags
)
{
    DEBUG_PRINT( );
    return 0;
}

bool ApuIsVirtualAddressValid_X(
         const void* virtualAddress,
         UINT32 physicalAlignmentInBytes
)
{
    DEBUG_PRINT( );
    return 0;
}
APU_ADDRESS ApuMapVirtualAddress_X(
         const void* virtualAddress
)
{
    DEBUG_PRINT( );
    return 0;
}

void* ApuMapApuAddress_X(
         APU_ADDRESS apuPhysicalAddress
)
{
    DEBUG_PRINT( );
    return 0;
}
