// ReSharper disable CppInconsistentNaming
#ifndef D3D11_X
#define D3D11_X

#include "dxgi1_5.h"
#include <d3d11.h>

typedef GUID DXGI_DEBUG_ID;

typedef enum D3D11_GRAPHICS_MEMORY_ACCESS_FLAG
{
    D3D11_GRAPHICS_MEMORY_ACCESS_CPU_CACHE_COHERENT = 0,
    D3D11_GRAPHICS_MEMORY_ACCESS_CPU_WRITECOMBINE_NONCOHERENT = 1,
    D3D11_GRAPHICS_MEMORY_ACCESS_CPU_CACHE_NONCOHERENT_GPU_READONLY = 2
} D3D11_GRAPHICS_MEMORY_ACCESS_FLAG;

typedef struct D3D11X_CREATE_DEVICE_PARAMETERS {
    UINT Version;
    UINT Flags;
    void* pOffchipTessellationBuffer;
    void* pTessellationFactorsBuffer;
    UINT DeferredDeletionThreadAffinityMask;
    UINT ImmediateContextDeRingSizeBytes;
    UINT ImmediateContextCeRingSizeBytes;
    UINT ImmediateContextDeSegmentSizeBytes;
    UINT ImmediateContextCeSegmentSizeBytes;
} D3D11X_CREATE_DEVICE_PARAMETERS;

extern "C" const GUID  DXGI_DEBUG_ALL;
DEFINE_GUID(DXGI_DEBUG_DX, 0x35cdd7fc, 0x13b2, 0x421d, 0xa5, 0xd7, 0x7e, 0x44, 0x51, 0x28, 0x7d, 0x64);
DEFINE_GUID(DXGI_DEBUG_DXGI, 0x25cddaa4, 0xb1c6, 0x47e1, 0xac, 0x3e, 0x98, 0x87, 0x5b, 0x5a, 0x2e, 0x2a);
DEFINE_GUID(DXGI_DEBUG_APP, 0x6cd6e01, 0x4219, 0x4ebd, 0x87, 0x9, 0x27, 0xed, 0x23, 0x36, 0xc, 0x62);

DEFINE_GUID(DXGI_DEBUG_D3D11, 0x4b99317b, 0xac39, 0x4aa6, 0xbb, 0xb, 0xba, 0xa0, 0x47, 0x84, 0x79, 0x8f);

#endif