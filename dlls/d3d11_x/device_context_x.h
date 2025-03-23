#pragma once
#include <array>
#include <map>

#include "device_child_x.h"
#include "device_x.h"

static std::map<UINT64, int> D3D11X_HARDWARE_TO_TOPOLOGY_MAP = {
	{0x000001ffc0009e00, 0}, {0x000003ffc0009e00, 1}, {0x000005ffc0009e00, 2}, {0x000007ffc0009e00, 3},
	{0x000009ffc0009e00, 4}, {0x00000dffc0009e00, 5}, {0x00000bffc0009e00, 6}, {0x000001ffc0009e00, 7},
	{0x000001ffc0009e00, 8}, {0x000001ffc0009e00, 9}, {0x0000157fc0009e00, 10}, {0x0000177fc0009e00, 11},
	{0x0000197fc0009e00, 12}, {0x00001b7fc0009e00, 13}, {0x00001dffc0009e00, 14}, {0x00001fffc0009e00, 15},
	{0x000021ffc0009e00, 16}, {0x000023ffc0009e00, 17}, {0x000025ffc0009e00, 18}, {0x000027ffc0009e00, 19},
	{0x000029ffc0009e00, 20}, {0x00002bffc0009e00, 21}, {0x00002dffc0009e00, 22}, {0x00002fffc0009e00, 23},
	{0x000031ffc0009e00, 24}, {0x000033ffc0009e00, 25}, {0x000035ffc0009e00, 26}, {0x000037ffc0009e00, 27},
	{0x000039ffc0009e00, 28}, {0x000001ffc0009e00, 29}, {0x000001ffc0009e00, 30}, {0x000001ffc0009e00, 31},
	{0x000001ffc0009e00, 32}, {0x001013ffc0009e00, 33}, {0x0020137fc0009e00, 34}, {0x00301354c0009e00, 35},
	{0x0040133fc0009e00, 36}, {0x00501332c0009e00, 37}, {0x00601329c0009e00, 38}, {0x00701323c0009e00, 39},
	{0x0080131fc0009e00, 40}, {0x0090131bc0009e00, 41}, {0x00a01318c0009e00, 42}, {0x00b01316c0009e00, 43},
	{0x00c01314c0009e00, 44}, {0x00d01312c0009e00, 45}, {0x00e01311c0009e00, 46}, {0x00f01310c0009e00, 47},
	{0x0100130fc0009e00, 48}, {0x0110130ec0009e00, 49}, {0x0120130dc0009e00, 50}, {0x0130130cc0009e00, 51},
	{0x0140130bc0009e00, 52}, {0x0150130bc0009e00, 53}, {0x0160130ac0009e00, 54}, {0x0170130ac0009e00, 55},
	{0x01801309c0009e00, 56}, {0x01901309c0009e00, 57}, {0x01a01308c0009e00, 58}, {0x01b01308c0009e00, 59},
	{0x01c01308c0009e00, 60}, {0x01d01307c0009e00, 61}, {0x01e01307c0009e00, 62}, {0x01f01307c0009e00, 63},
	{0x02001307c0009e00, 64}
};

namespace wdi
{
	#pragma region struct_defs
	typedef enum _D3D11X_GDS_REGION_TYPE
	{
		D3D11X_GDS_REGION_PS = 0,
		D3D11X_GDS_REGION_CS = 1
	} D3D11X_GDS_REGION_TYPE;

	typedef struct D3D11X_COUNTER_DATA
	{
		UINT Size;
		UINT Version;

		UINT64 GRBM[ 2 ][ 1 ];
		UINT64 SRBM[ 2 ][ 1 ];
		UINT64 CPF[ 2 ][ 1 ];
		UINT64 CPG[ 2 ][ 1 ];
		UINT64 CPC[ 2 ][ 1 ];
		UINT64 CB[ 4 ][ 8 ];        // only 4 instances on Durango
		UINT64 DB[ 4 ][ 8 ];        // only 4 instances on Durango
		UINT64 SU[ 4 ][ 4 ];        // only 2 instances on Durango
		UINT64 SC[ 8 ][ 4 ];        // only 2 instances on Durango
		UINT64 SX[ 8 ][ 4 ];        // only 2 instances on Durango
		UINT64 SPI[ 4 ][ 4 ];       // only 2 instances on Durango
		UINT64 SQ[ 16 ][ 4 ];       // only 2 instances on Durango
		UINT64 TA[ 5 ][ 40 ];       // only 12 instances on Durango
		UINT64 TD[ 2 ][ 40 ];       // only 12 instances on Durango
		UINT64 TCP[ 8 ][ 40 ];      // only 12 instances on Durango
		UINT64 TCC[ 4 ][ 8 ];       // only 4 instances on Durango
		UINT64 TCA[ 4 ][ 2 ];
		UINT64 GDS[ 4 ][ 1 ];
		UINT64 VGT[ 4 ][ 4 ];       // only 2 instances on Durango
		UINT64 IA[ 4 ][ 2 ];        // only 1 instances on Durango
		UINT64 WD[ 4 ][ 1 ];
		UINT64 MC_MCB_L1TLB[ 4 ][ 1 ];
		UINT64 MC_HV_MCB_L1TLB[ 4 ][ 1 ];
		UINT64 MC_MCD_L1TLB[ 4 ][ 2 ];
		UINT64 MC_HV_MCD_L1TLB[ 4 ][ 2 ];
		UINT64 MC_L2TLB[ 2 ][ 1 ];
		UINT64 MC_HV_L2TLB[ 2 ][ 1 ];
		UINT64 MC_ARB[ 4 ][ 6 ];    // only 2 instances on Durango
		UINT64 MC_CITF[ 4 ][ 4 ];   // only 2 instances on Duragno
		UINT64 MC_HUB[ 4 ][ 1 ];
		UINT64 GRN[ 4 ][ 1 ];       // only 1 instance on Druango
		UINT64 GRN1[ 4 ][ 1 ];      // not valid on Durango
		UINT64 GRN2[ 4 ][ 1 ];      // not valid on Durango
	} D3D11X_COUNTER_DATA;

	typedef enum D3D11_STAGE : UINT
	{
		D3D11_STAGE_VS = 0,
		D3D11_STAGE_HS = 1,
		D3D11_STAGE_DS = 2,
		D3D11_STAGE_GS = 3,
		D3D11_STAGE_PS = 4,
		D3D11_STAGE_CS = 5
	} D3D11_STAGE;

	typedef struct D3D11X_TESSELLATION_PARAMETERS
	{
		UINT  Size;
		UINT  Flags;
		UINT  PatchesPerThreadgroup;
		float TfThreshold;
		UINT  DsWaveThreshold;
	} D3D11X_TESSELLATION_PARAMETERS;

	typedef enum D3D11X_GPU_PIPELINED_EVENT
	{
		D3D11X_GPU_PIPELINED_EVENT_STREAMOUT_FLUSH = 0x0000001f,   // Flush stream out caches
		D3D11X_GPU_PIPELINED_EVENT_FLUSH_AND_INV_CB_PIXEL_DATA = 0x00000031,   // Flush Color Block data
		D3D11X_GPU_PIPELINED_EVENT_DB_CACHE_FLUSH_AND_INV = 0x0000002a,   // Flush Depth Block data
		D3D11X_GPU_PIPELINED_EVENT_FLUSH_AND_INV_CB_META = 0x0000002e,   // Flush Color Block metadata
		D3D11X_GPU_PIPELINED_EVENT_FLUSH_AND_INV_DB_META = 0x0000002c,   // Flush Depth Block metadata
		D3D11X_GPU_PIPELINED_EVENT_CS_PARTIAL_FLUSH = 0x00000407,   // Ensure all CS finished running before dispatching new CS
		D3D11X_GPU_PIPELINED_EVENT_VS_PARTIAL_FLUSH = 0x0000040f,   // Ensure all VS finished running before dispatching new VS
		D3D11X_GPU_PIPELINED_EVENT_PS_PARTIAL_FLUSH = 0x00000410,   // Ensure all PS finished running before dispatching new PS
		D3D11X_GPU_PIPELINED_EVENT_PFP_SYNC_ME = 0x80000001,   // Synchronize command processor PFP with ME

	} D3D11X_GPU_PIPELINED_EVENT;

	struct D3D11X_GRAPHICS_SHADER_LIMITS
	{
		UINT MaxWavesWithLateAllocParameterCache;

		UINT VSDisableCuMask;
		// Note: HS must run in the same CU as VS, so it has no mask of its own.
		UINT DSDisableCuMask;
		UINT GSDisableCuMask;
		UINT PSDisableCuMask;

		UINT VSMaxWaves;
		UINT HSMaxWaves;
		UINT DSMaxWaves;
		UINT GSMaxWaves;
		UINT PSMaxWaves;

		UINT VSMaxWavesForCuLocking;
		UINT HSMaxWavesForCuLocking;
		UINT DSMaxWavesForCuLocking;
		UINT GSMaxWavesForCuLocking;
		UINT PSMaxWavesForCuLocking;
	};

	enum D3D11X_SHADER_CS_SIMD_WALK_ALGORITHM : UINT
	{
		D3D11X_SHADER_CS_SIMD_WALK_ALGORITHM_DEFAULT = 0,
		D3D11X_SHADER_CS_SIMD_WALK_ALGORITHM_GLOBAL_BALANCED = 1, // Walk the SIMDs across CUs but maintaining a balanced distribution per CU.
		D3D11X_SHADER_CS_SIMD_WALK_ALGORITHM_GLOBAL_STRICT = 2, // Walk the SIMDs across CUs disregarding wave distribution within each CU.
		D3D11X_SHADER_CS_SIMD_WALK_ALGORITHM_PER_CU = 3, // Walk SIMDs independently for each CU.
	};

	struct D3D11X_COMPUTE_SHADER_LIMITS
	{
		UINT                                 DisableCuMask[ 2 ];
		UINT                                 MaxWaves;
		UINT                                 MaxThreadgroupsPerCu;
		UINT                                 MaxWavesForCuLocking;
		UINT                                 NumThreadgroupsWalkedPerCu;
		D3D11X_SHADER_CS_SIMD_WALK_ALGORITHM SimdWalkAlgorithm;
	};

	typedef enum D3D11X_THREAD_TRACE_SCOPE
	{
		D3D11X_THREAD_TRACE_SCOPE_TITLE_ONLY = 0,
		D3D11X_THREAD_TRACE_SCOPE_SYSTEM_WIDE = 1,
		D3D11X_THREAD_TRACE_SCOPE_SYSTEM_AND_DETAILED_TITLE = 2,
	} D3D11X_THREAD_TRACE_SCOPE;

	typedef enum D3D11X_THREAD_TRACE_PIPELINE_ENABLE
	{
		D3D11X_THREAD_TRACE_PIPELINE_ENABLE_NONE = 0x00000000, //  Don't trace threads of this type 
		D3D11X_THREAD_TRACE_PIPELINE_ENABLE_ALL = 0x00000001, //  Trace target-CU details for all threads of this type when tracing is enabled 
	} D3D11X_THREAD_TRACE_PIPELINE_ENABLE;

	struct D3D11X_THREAD_TRACE_DESC
	{
		BOOL PipelineFlushBeforeAndAfter;
		UINT TargetComputeUnitIndex;
		D3D11X_THREAD_TRACE_SCOPE TraceScope;
		BOOL AllowSamplingGpuStalls;
		D3D11X_THREAD_TRACE_PIPELINE_ENABLE PsEnable;
		D3D11X_THREAD_TRACE_PIPELINE_ENABLE VsEnable;
		D3D11X_THREAD_TRACE_PIPELINE_ENABLE GsEnable;
		D3D11X_THREAD_TRACE_PIPELINE_ENABLE EsEnable;
		D3D11X_THREAD_TRACE_PIPELINE_ENABLE HsEnable;
		D3D11X_THREAD_TRACE_PIPELINE_ENABLE LsEnable;
		D3D11X_THREAD_TRACE_PIPELINE_ENABLE CsEnable;
		USHORT TokenMask;
		USHORT InstructionMask;
		BYTE RegisterMask;
	};

	typedef struct D3D11X_GS_PARAMETERS
	{
		UINT  Size;
		UINT  Flags;
		UINT  VerticesPerSubgroup;
		UINT  PrimitivesPerSubgroup;
		float VerticesPerPrimitiveRatio;
		UINT  LdsAllocationLimit;
	} D3D11X_GS_PARAMETERS;

	typedef struct _D3D11X_MSAA_SCAN_CONVERTER_SETTINGS
	{
		UINT        NumSamplesMsaaLog2 : 3;
		UINT        MaxSampleDistanceInSubpixels : 4;
		UINT        NumSamplesMsaaExposedToPSLog2 : 3;
		UINT        DetailToExposedMode : 2;
		UINT        ApplyMaskAfterCentroid : 1;
	} D3D11X_MSAA_SCAN_CONVERTER_SETTINGS;

	typedef POINT D3D11X_POINT;

	typedef struct  _D3D11X_MSAA_EQAA_SETTINGS
	{
		UINT        MaxAnchorSamplesLog2 : 3;
		UINT        NumSamplesForPSIterationLog2 : 3;
		UINT        NumSamplesForMaskExportLog2 : 3;
		UINT        NumSamplesForAlphaToMaskLog2 : 3;
		UINT        HightQualityIntersections : 1;
		UINT        InterpolateCompZ : 1;
		UINT        InterpolateSrcZ : 1;
		UINT        StaticAnchorAssociations : 1;
		UINT        OverrasterizationAmount : 3;
		UINT        EnablePostZOverrasterization : 1;
	} D3D11X_MSAA_EQAA_SETTINGS;

	typedef struct _D3D11X_MSAA_SAMPLE_PRIORITIES
	{
		BYTE        CentroidPriorities[ 16 ];
	} D3D11X_MSAA_SAMPLE_PRIORITIES;

	typedef struct _D3D11X_MSAA_SAMPLE_POSITIONS
	{
		INT8  SampleLocs00[ 16 ][ 2 ];  // Sample positions stored as one byte per component, X then Y
		INT8  SampleLocs10[ 16 ][ 2 ];  // There are up to 16 possible sample positions per pixel
		INT8  SampleLocs01[ 16 ][ 2 ];  // They can be set differently for each pixel in a 2x2 quad
		INT8  SampleLocs11[ 16 ][ 2 ];
	} D3D11X_MSAA_SAMPLE_POSITIONS;

	typedef D3D11_RECT D3D11X_RECT;

	typedef struct D3D11X_FORMAT
	{
		union
		{
			struct
			{
				// these are some other enum, too lazy to import them
				UINT DataFormat;
				UINT NumberFormat;
			};
			UINT32 Dword[ 2 ];
			UINT64 Qword;
		};
	} D3D11X_FORMAT;

	typedef enum D3D11X_HW_STAGE : UINT
	{
		D3D11X_HW_STAGE_PS = 0,
		D3D11X_HW_STAGE_VS = 1,
		D3D11X_HW_STAGE_GS = 2,
		D3D11X_HW_STAGE_ES = 3,
		D3D11X_HW_STAGE_HS = 4,
		D3D11X_HW_STAGE_LS = 5,
		D3D11X_HW_STAGE_CS = 6,
	} D3D11X_HW_STAGE;
	#pragma endregion

	// FIXME: handle different versions of the SDK for this class
	D3DINTERFACE(ID3D11DeviceContext, c0bfa96c, e089, 44fb, 8e, af, 26, f8, 79, 61, 90, da) : public ID3D11DeviceChild {
	public:
		virtual void (VSSetConstantBuffers)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_In_reads_opt_(NumBuffers) ID3D11Buffer* const* ppConstantBuffers) = 0;
		virtual void (PSSetShaderResources)(ID3D11ShaderResourceView* const* ppShaderResourceViews,_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT StartSlot,_In_ UINT PacketHeader) = 0;
		virtual void (PSSetShader)(_In_opt_ ID3D11PixelShader* pPixelShader) = 0;
		virtual void (PSSetSamplers)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - StartSlot) UINT NumSamplers,_In_reads_opt_(NumSamplers) ID3D11SamplerState* const* ppSamplers) = 0;
		virtual void (VSSetShader)(_In_opt_ ID3D11VertexShader* pVertexShader) = 0;
		virtual void (DrawIndexed)(_In_ UINT64 StartIndexLocationAndIndexCount,_In_ INT BaseVertexLocation) = 0;
		virtual void (Draw)(_In_ UINT VertexCount,_In_ UINT StartVertexLocation) = 0;
		virtual HRESULT(Map)(_In_ ID3D11Resource* pResource,_In_ UINT Subresource,_In_ D3D11_MAP MapType,_In_ UINT MapFlags,_Out_ D3D11_MAPPED_SUBRESOURCE* pMappedResource) = 0;
		virtual void (Unmap)(_In_ ID3D11Resource* pResource,_In_ UINT Subresource) = 0;
		virtual void (PSSetConstantBuffers)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_In_reads_opt_(NumBuffers) ID3D11Buffer* const* ppConstantBuffers) = 0;
		virtual void (IASetInputLayout)(_In_opt_ ID3D11InputLayout* pInputLayout) = 0;
		virtual void (IASetVertexBuffers)(_In_range_(0, D3D11_IA_VERTEX_INPUT_RESOURCE_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_IA_VERTEX_INPUT_RESOURCE_SLOT_COUNT - StartSlot) UINT NumBuffers,_In_reads_opt_(NumBuffers) ID3D11Buffer* const* ppVertexBuffers,_In_reads_opt_(NumBuffers) const UINT* pStrides,_In_reads_opt_(NumBuffers) const UINT* pOffsets) = 0;
		virtual void (IASetIndexBuffer)(_In_ UINT HardwareIndexFormat,_In_opt_ ID3D11Buffer* pIndexBuffer,_In_ UINT Offset) = 0;
		virtual void (DrawIndexedInstanced)(_In_ UINT64 StartIndexLocationAndIndexCountPerInstance,_In_ UINT64 BaseVertexLocationAndStartInstanceLocation,_In_ UINT InstanceCount) = 0;
		virtual void (DrawInstanced)(_In_ UINT VertexCountPerInstance,_In_ UINT64 StartVertexLocationAndStartInstanceLocation,_In_ UINT InstanceCount) = 0;
		virtual void (GSSetConstantBuffers)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_In_reads_opt_(NumBuffers) ID3D11Buffer* const* ppConstantBuffers) = 0;
		virtual void (GSSetShader)(_In_opt_ ID3D11GeometryShader* pShader) = 0;
		virtual void (VSSetShaderResources)(ID3D11ShaderResourceView* const* ppShaderResourceViews,_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT StartSlot,_In_ UINT PacketHeader) = 0;
		virtual void (VSSetSamplers)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - StartSlot) UINT NumSamplers,_In_reads_opt_(NumSamplers) ID3D11SamplerState* const* ppSamplers) = 0;
		virtual void (Begin)(_In_ ID3D11Asynchronous* pAsync) = 0;
		virtual void (End)(_In_ ID3D11Asynchronous* pAsync) = 0;
		virtual HRESULT(GetData)(_In_ ID3D11Asynchronous* pAsync,_Out_writes_bytes_opt_(DataSize) void* pData,_In_ UINT DataSize,_In_ UINT GetDataFlags) = 0;
		virtual void (SetPredication)(_In_opt_ ID3D11Predicate* pPredicate,_In_ BOOL PredicateValue) = 0;
		virtual void (GSSetShaderResources)(ID3D11ShaderResourceView* const* ppShaderResourceViews,_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT StartSlot,_In_ UINT PacketHeader) = 0;
		virtual void (GSSetSamplers)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - StartSlot) UINT NumSamplers,_In_reads_opt_(NumSamplers) ID3D11SamplerState* const* ppSamplers) = 0;
		virtual void (OMSetRenderTargets)(_In_range_(0, D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT) UINT NumViews,_In_reads_opt_(NumViews) ID3D11RenderTargetView* const* ppRenderTargetViews,_In_opt_ ID3D11DepthStencilView* pDepthStencilView) = 0;
		virtual void (OMSetRenderTargetsAndUnorderedAccessViews)(_In_ UINT NumRTVs,_In_reads_opt_(NumRTVs) ID3D11RenderTargetView* const* ppRenderTargetViews,_In_opt_ ID3D11DepthStencilView* pDepthStencilView,_In_range_(0, D3D11_1_UAV_SLOT_COUNT - 1) UINT UAVStartSlot,_In_ UINT NumUAVs,_In_reads_opt_(NumUAVs) ID3D11UnorderedAccessView* const* ppUnorderedAccessViews,_In_reads_opt_(NumUAVs) const UINT* pUAVInitialCounts) = 0;
		virtual void (OMSetBlendState)(_In_opt_ ID3D11BlendState* pBlendState,_In_opt_ const FLOAT BlendFactor[ 4 ],_In_ UINT SampleMask) = 0;
		virtual void (OMSetDepthStencilState)(_In_opt_ ID3D11DepthStencilState* pDepthStencilState,_In_ UINT StencilRef) = 0;
		virtual void (SOSetTargets)(_In_range_(0, D3D11_SO_BUFFER_SLOT_COUNT) UINT NumBuffers,_In_reads_opt_(NumBuffers) ID3D11Buffer* const* ppSOTargets,_In_reads_opt_(NumBuffers) const UINT* pOffsets) = 0;
		virtual void (DrawAuto)( ) = 0;
		virtual void (DrawIndexedInstancedIndirect)(_In_ ID3D11Buffer* pBufferForArgs,_In_ UINT AlignedByteOffsetForArgs) = 0;
		virtual void (DrawInstancedIndirect)(_In_ ID3D11Buffer* pBufferForArgs,_In_ UINT AlignedByteOffsetForArgs) = 0;
		virtual void (Dispatch)(_In_ UINT ThreadGroupCountX,_In_ UINT ThreadGroupCountY,_In_ UINT ThreadGroupCountZ) = 0;
		virtual void (DispatchIndirect)(_In_ ID3D11Buffer* pBufferForArgs,_In_ UINT AlignedByteOffsetForArgs) = 0;
		virtual void (RSSetState)(_In_opt_ ID3D11RasterizerState* pRasterizerState) = 0;
		virtual void (RSSetViewports)(_In_range_(0, D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE) UINT NumViewports,_In_reads_opt_(NumViewports) const D3D11_VIEWPORT* pViewports) = 0;
		virtual void (RSSetScissorRects)(_In_range_(0, D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE) UINT NumRects,_In_reads_opt_(NumRects) const D3D11_RECT* pRects) = 0;
		virtual void (CopySubresourceRegion)(_In_ ID3D11Resource* pDstResource,_In_ UINT DstSubresource,_In_ UINT DstX,_In_ UINT DstY,_In_ UINT DstZ,_In_ ID3D11Resource* pSrcResource,_In_ UINT SrcSubresource,_In_opt_ const D3D11_BOX* pSrcBox) = 0;
		virtual void (CopyResource)(_In_ ID3D11Resource* pDstResource,_In_ ID3D11Resource* pSrcResource) = 0;
		virtual void (UpdateSubresource)(_In_ ID3D11Resource* pDstResource,_In_ UINT DstSubresource,_In_opt_ const D3D11_BOX* pDstBox,_In_ const void* pSrcData,_In_ UINT SrcRowPitch,_In_ UINT SrcDepthPitch) = 0;
		virtual void (CopyStructureCount)(_In_ ID3D11Buffer* pDstBuffer,_In_ UINT DstAlignedByteOffset,_In_ ID3D11UnorderedAccessView* pSrcView) = 0;
		virtual void (ClearRenderTargetView)(_In_ ID3D11RenderTargetView* pRenderTargetView,_In_ const FLOAT ColorRGBA[ 4 ]) = 0;
		virtual void (ClearUnorderedAccessViewUint)(_In_ ID3D11UnorderedAccessView* pUnorderedAccessView,_In_ const UINT Values[ 4 ]) = 0;
		virtual void (ClearUnorderedAccessViewFloat)(_In_ ID3D11UnorderedAccessView* pUnorderedAccessView,_In_ const FLOAT Values[ 4 ]) = 0;
		virtual void (ClearDepthStencilView)(_In_ ID3D11DepthStencilView* pDepthStencilView,_In_ UINT ClearFlags,_In_ FLOAT Depth,_In_ UINT8 Stencil) = 0;
		virtual void (GenerateMips)(_In_ ID3D11ShaderResourceView* pShaderResourceView) = 0;
		virtual void (SetResourceMinLOD)(_In_ ID3D11Resource* pResource,FLOAT MinLOD) = 0;
		virtual FLOAT(GetResourceMinLOD)(_In_ ID3D11Resource* pResource) = 0;
		virtual void (ResolveSubresource)(_In_ ID3D11Resource* pDstResource,_In_ UINT DstSubresource,_In_ ID3D11Resource* pSrcResource,_In_ UINT SrcSubresource,_In_ DXGI_FORMAT Format) = 0;
		virtual void (ExecuteCommandList)(_In_ ID3D11CommandList* pCommandList,BOOL RestoreContextState) = 0;
		virtual void (HSSetShaderResources)(ID3D11ShaderResourceView* const* ppShaderResourceViews,_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT StartSlot,_In_ UINT PacketHeader) = 0;
		virtual void (HSSetShader)(_In_opt_ ID3D11HullShader* pHullShader) = 0;
		virtual void (HSSetSamplers)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - StartSlot) UINT NumSamplers,_In_reads_opt_(NumSamplers) ID3D11SamplerState* const* ppSamplers) = 0;
		virtual void (HSSetConstantBuffers)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_In_reads_opt_(NumBuffers) ID3D11Buffer* const* ppConstantBuffers) = 0;
		virtual void (DSSetShaderResources)(ID3D11ShaderResourceView* const* ppShaderResourceViews,_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT StartSlot,_In_ UINT PacketHeader) = 0;
		virtual void (DSSetShader)(_In_opt_ ID3D11DomainShader* pDomainShader) = 0;
		virtual void (DSSetSamplers)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - StartSlot) UINT NumSamplers,_In_reads_opt_(NumSamplers) ID3D11SamplerState* const* ppSamplers) = 0;
		virtual void (DSSetConstantBuffers)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_In_reads_opt_(NumBuffers) ID3D11Buffer* const* ppConstantBuffers) = 0;
		virtual void (CSSetShaderResources)(ID3D11ShaderResourceView* const* ppShaderResourceViews,_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT StartSlot,_In_ UINT PacketHeader) = 0;
		virtual void (CSSetUnorderedAccessViews)(_In_range_(0, D3D11_1_UAV_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_1_UAV_SLOT_COUNT - StartSlot) UINT NumUAVs,_In_reads_opt_(NumUAVs) ID3D11UnorderedAccessView* const* ppUnorderedAccessViews,_In_reads_opt_(NumUAVs) const UINT* pUAVInitialCounts) = 0;
		virtual void (CSSetShader)(_In_opt_ ID3D11ComputeShader* pComputeShader) = 0;
		virtual void (CSSetSamplers)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - StartSlot) UINT NumSamplers,_In_reads_opt_(NumSamplers) ID3D11SamplerState* const* ppSamplers) = 0;
		virtual void (CSSetConstantBuffers)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_In_reads_opt_(NumBuffers) ID3D11Buffer* const* ppConstantBuffers) = 0;
		virtual void (VSGetConstantBuffers)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_Out_writes_opt_(NumBuffers) ID3D11Buffer** ppConstantBuffers) = 0;
		virtual void (PSGetShaderResources)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - StartSlot) UINT NumViews,_Out_writes_opt_(NumViews) ID3D11ShaderResourceView** ppShaderResourceViews) = 0;
		virtual void (PSGetShader)(_Out_ ID3D11PixelShader** ppPixelShader,_Out_writes_opt_(*pNumClassInstances) ID3D11ClassInstance** ppClassInstances,_Inout_opt_ UINT* pNumClassInstances) = 0;
		virtual void (PSGetSamplers)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - StartSlot) UINT NumSamplers,_Out_writes_opt_(NumSamplers) ID3D11SamplerState** ppSamplers) = 0;
		virtual void (VSGetShader)(_Out_ ID3D11VertexShader** ppVertexShader,_Out_writes_opt_(*pNumClassInstances) ID3D11ClassInstance** ppClassInstances,_Inout_opt_ UINT* pNumClassInstances) = 0;
		virtual void (PSGetConstantBuffers)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_Out_writes_opt_(NumBuffers) ID3D11Buffer** ppConstantBuffers) = 0;
		virtual void (IAGetInputLayout)(_Out_ ID3D11InputLayout** ppInputLayout) = 0;
		virtual void (IAGetVertexBuffers)(_In_range_(0, D3D11_IA_VERTEX_INPUT_RESOURCE_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_IA_VERTEX_INPUT_RESOURCE_SLOT_COUNT - StartSlot) UINT NumBuffers,_Out_writes_opt_(NumBuffers) ID3D11Buffer** ppVertexBuffers,_Out_writes_opt_(NumBuffers) UINT* pStrides,_Out_writes_opt_(NumBuffers) UINT* pOffsets) = 0;
		virtual void (IAGetIndexBuffer)(_Out_opt_ ID3D11Buffer** pIndexBuffer,_Out_opt_ DXGI_FORMAT* Format,_Out_opt_ UINT* Offset) = 0;
		virtual void (GSGetConstantBuffers)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_Out_writes_opt_(NumBuffers) ID3D11Buffer** ppConstantBuffers) = 0;
		virtual void (GSGetShader)(_Out_ ID3D11GeometryShader** ppGeometryShader,_Out_writes_opt_(*pNumClassInstances) ID3D11ClassInstance** ppClassInstances,_Inout_opt_ UINT* pNumClassInstances) = 0;
		virtual void (IAGetPrimitiveTopology)(_Out_ D3D11_PRIMITIVE_TOPOLOGY* pTopology) = 0;
		virtual void (VSGetShaderResources)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - StartSlot) UINT NumViews,_Out_writes_opt_(NumViews) ID3D11ShaderResourceView** ppShaderResourceViews) = 0;
		virtual void (VSGetSamplers)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - StartSlot) UINT NumSamplers,_Out_writes_opt_(NumSamplers) ID3D11SamplerState** ppSamplers) = 0;
		virtual void (GetPredication)(_Out_opt_ ID3D11Predicate** ppPredicate,_Out_opt_ BOOL* pPredicateValue) = 0;
		virtual void (GSGetShaderResources)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - StartSlot) UINT NumViews,_Out_writes_opt_(NumViews) ID3D11ShaderResourceView** ppShaderResourceViews) = 0;
		virtual void (GSGetSamplers)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - StartSlot) UINT NumSamplers,_Out_writes_opt_(NumSamplers) ID3D11SamplerState** ppSamplers) = 0;
		virtual void (OMGetRenderTargets)(_In_range_(0, D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT) UINT NumViews,_Out_writes_opt_(NumViews) ID3D11RenderTargetView** ppRenderTargetViews,_Out_opt_ ID3D11DepthStencilView** ppDepthStencilView) = 0;
		virtual void (OMGetRenderTargetsAndUnorderedAccessViews)(_In_range_(0, D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT) UINT NumRTVs,_Out_writes_opt_(NumRTVs) ID3D11RenderTargetView** ppRenderTargetViews,_Out_opt_ ID3D11DepthStencilView** ppDepthStencilView,_In_range_(0, D3D11_PS_CS_UAV_REGISTER_COUNT - 1) UINT UAVStartSlot,_In_range_(0, D3D11_PS_CS_UAV_REGISTER_COUNT - UAVStartSlot) UINT NumUAVs,_Out_writes_opt_(NumUAVs) ID3D11UnorderedAccessView** ppUnorderedAccessViews) = 0;
		virtual void (OMGetBlendState)(_Out_opt_ ID3D11BlendState** ppBlendState,_Out_writes_all_opt_(4) FLOAT BlendFactor[ 4 ],_Out_opt_ UINT* pSampleMask) = 0;
		virtual void (OMGetDepthStencilState)(_Out_opt_ ID3D11DepthStencilState** ppDepthStencilState,_Out_opt_ UINT* pStencilRef) = 0;
		virtual void (SOGetTargets)(_In_range_(0, D3D11_SO_BUFFER_SLOT_COUNT) UINT NumBuffers,_Out_writes_opt_(NumBuffers) ID3D11Buffer** ppSOTargets) = 0;
		virtual void (RSGetState)(_Out_ ID3D11RasterizerState** ppRasterizerState) = 0;
		virtual void (RSGetViewports)(_Inout_ /*_range(0, D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE )*/ UINT* pNumViewports,_Out_writes_opt_(*pNumViewports) D3D11_VIEWPORT* pViewports) = 0;
		virtual void (RSGetScissorRects)(_Inout_ /*_range(0, D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE )*/ UINT* pNumRects,_Out_writes_opt_(*pNumRects) D3D11_RECT* pRects) = 0;
		virtual void (HSGetShaderResources)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - StartSlot) UINT NumViews,_Out_writes_opt_(NumViews) ID3D11ShaderResourceView** ppShaderResourceViews) = 0;
		virtual void (HSGetShader)(_Out_ ID3D11HullShader** ppHullShader,_Out_writes_opt_(*pNumClassInstances) ID3D11ClassInstance** ppClassInstances,_Inout_opt_ UINT* pNumClassInstances) = 0;
		virtual void (HSGetSamplers)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - StartSlot) UINT NumSamplers,_Out_writes_opt_(NumSamplers) ID3D11SamplerState** ppSamplers) = 0;
		virtual void (HSGetConstantBuffers)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_Out_writes_opt_(NumBuffers) ID3D11Buffer** ppConstantBuffers) = 0;
		virtual void (DSGetShaderResources)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - StartSlot) UINT NumViews,_Out_writes_opt_(NumViews) ID3D11ShaderResourceView** ppShaderResourceViews) = 0;
		virtual void (DSGetShader)(_Out_ ID3D11DomainShader** ppDomainShader,_Out_writes_opt_(*pNumClassInstances) ID3D11ClassInstance** ppClassInstances,_Inout_opt_ UINT* pNumClassInstances) = 0;
		virtual void (DSGetSamplers)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - StartSlot) UINT NumSamplers,_Out_writes_opt_(NumSamplers) ID3D11SamplerState** ppSamplers) = 0;
		virtual void (DSGetConstantBuffers)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_Out_writes_opt_(NumBuffers) ID3D11Buffer** ppConstantBuffers) = 0;
		virtual void (CSGetShaderResources)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - StartSlot) UINT NumViews,_Out_writes_opt_(NumViews) ID3D11ShaderResourceView** ppShaderResourceViews) = 0;
		virtual void (CSGetUnorderedAccessViews)(_In_range_(0, D3D11_PS_CS_UAV_REGISTER_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_PS_CS_UAV_REGISTER_COUNT - StartSlot) UINT NumUAVs,_Out_writes_opt_(NumUAVs) ID3D11UnorderedAccessView** ppUnorderedAccessViews) = 0;
		virtual void (CSGetShader)(_Out_ ID3D11ComputeShader** ppComputeShader,_Out_writes_opt_(*pNumClassInstances) ID3D11ClassInstance** ppClassInstances,_Inout_opt_ UINT* pNumClassInstances) = 0;
		virtual void (CSGetSamplers)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - StartSlot) UINT NumSamplers,_Out_writes_opt_(NumSamplers) ID3D11SamplerState** ppSamplers) = 0;
		virtual void (CSGetConstantBuffers)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_Out_writes_opt_(NumBuffers) ID3D11Buffer** ppConstantBuffers) = 0;
		virtual void (ClearState)( ) = 0;
		virtual void (Flush)( ) = 0;
		virtual D3D11_DEVICE_CONTEXT_TYPE(GetType)() = 0;
		virtual UINT(GetContextFlags)() = 0;
		virtual HRESULT(FinishCommandList)(BOOL RestoreDeferredContextState,_Out_opt_ ID3D11CommandList** ppCommandList) = 0;
	};

	// this class remains the same for all versions of d3d11.x
	D3DINTERFACE(ID3D11DeviceContext1, bb2c6faa, b5fb, 4082, 8e, 6b, 38, 8b, 8c, fa, 90, e1) : public ID3D11DeviceContext {
	public:
		virtual void (CopySubresourceRegion1)(_In_ ID3D11Resource* pDstResource,_In_ UINT DstSubresource,_In_ UINT DstX,_In_ UINT DstY,_In_ UINT DstZ,_In_ ID3D11Resource* pSrcResource,_In_ UINT SrcSubresource,_In_opt_ const D3D11_BOX* pSrcBox,_In_ UINT CopyFlags) = 0;
		virtual void (UpdateSubresource1)(_In_ ID3D11Resource* pDstResource,_In_ UINT DstSubresource,_In_opt_ const D3D11_BOX* pDstBox,_In_ const void* pSrcData,_In_ UINT SrcRowPitch,_In_ UINT SrcDepthPitch,_In_ UINT CopyFlags) = 0;
		virtual void (DiscardResource)(_In_ ID3D11Resource* pResource) = 0;
		virtual void (DiscardView)(_In_ ID3D11View* pResourceView) = 0;
		virtual void (VSSetConstantBuffers1)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_In_reads_opt_(NumBuffers) ID3D11Buffer* const* ppConstantBuffers,_In_reads_opt_(NumBuffers) const UINT* pFirstConstant,_In_reads_opt_(NumBuffers) const UINT* pNumConstants) = 0;
		virtual void (HSSetConstantBuffers1)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_In_reads_opt_(NumBuffers) ID3D11Buffer* const* ppConstantBuffers,_In_reads_opt_(NumBuffers) const UINT* pFirstConstant,_In_reads_opt_(NumBuffers) const UINT* pNumConstants) = 0;
		virtual void (DSSetConstantBuffers1)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_In_reads_opt_(NumBuffers) ID3D11Buffer* const* ppConstantBuffers,_In_reads_opt_(NumBuffers) const UINT* pFirstConstant,_In_reads_opt_(NumBuffers) const UINT* pNumConstants) = 0;
		virtual void (GSSetConstantBuffers1)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_In_reads_opt_(NumBuffers) ID3D11Buffer* const* ppConstantBuffers,_In_reads_opt_(NumBuffers) const UINT* pFirstConstant,_In_reads_opt_(NumBuffers) const UINT* pNumConstants) = 0;
		virtual void (PSSetConstantBuffers1)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_In_reads_opt_(NumBuffers) ID3D11Buffer* const* ppConstantBuffers,_In_reads_opt_(NumBuffers) const UINT* pFirstConstant,_In_reads_opt_(NumBuffers) const UINT* pNumConstants) = 0;
		virtual void (CSSetConstantBuffers1)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_In_reads_opt_(NumBuffers) ID3D11Buffer* const* ppConstantBuffers,_In_reads_opt_(NumBuffers) const UINT* pFirstConstant,_In_reads_opt_(NumBuffers) const UINT* pNumConstants) = 0;
		virtual void (VSGetConstantBuffers1)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_Out_writes_opt_(NumBuffers) ID3D11Buffer** ppConstantBuffers,_Out_writes_opt_(NumBuffers) UINT* pFirstConstant,_Out_writes_opt_(NumBuffers) UINT* pNumConstants) = 0;
		virtual void (HSGetConstantBuffers1)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_Out_writes_opt_(NumBuffers) ID3D11Buffer** ppConstantBuffers,_Out_writes_opt_(NumBuffers) UINT* pFirstConstant,_Out_writes_opt_(NumBuffers) UINT* pNumConstants) = 0;
		virtual void (DSGetConstantBuffers1)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_Out_writes_opt_(NumBuffers) ID3D11Buffer** ppConstantBuffers,_Out_writes_opt_(NumBuffers) UINT* pFirstConstant,_Out_writes_opt_(NumBuffers) UINT* pNumConstants) = 0;
		virtual void (GSGetConstantBuffers1)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_Out_writes_opt_(NumBuffers) ID3D11Buffer** ppConstantBuffers,_Out_writes_opt_(NumBuffers) UINT* pFirstConstant,_Out_writes_opt_(NumBuffers) UINT* pNumConstants) = 0;
		virtual void (PSGetConstantBuffers1)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_Out_writes_opt_(NumBuffers) ID3D11Buffer** ppConstantBuffers,_Out_writes_opt_(NumBuffers) UINT* pFirstConstant,_Out_writes_opt_(NumBuffers) UINT* pNumConstants) = 0;
		virtual void (CSGetConstantBuffers1)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT StartSlot,_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - StartSlot) UINT NumBuffers,_Out_writes_opt_(NumBuffers) ID3D11Buffer** ppConstantBuffers,_Out_writes_opt_(NumBuffers) UINT* pFirstConstant,_Out_writes_opt_(NumBuffers) UINT* pNumConstants) = 0;
		virtual void (SwapDeviceContextState)(_In_ ID3DDeviceContextState* pState,_Out_opt_ ID3DDeviceContextState** ppPreviousState) = 0;
		virtual void (ClearView)(_In_ ID3D11View* pView,_In_ const FLOAT Color[ 4 ],_In_reads_opt_(NumRects) const D3D11_RECT* pRect,UINT NumRects) = 0;
		virtual void (DiscardView1)(_In_ ID3D11View* pResourceView,_In_reads_opt_(NumRects) const D3D11_RECT* pRects,UINT NumRects) = 0;
	};

	D3DINTERFACE(ID3D11DeviceContext2, 420d5b32, b90c, 4da4, be, f0, 35, 9f, 6a, 24, a8, 3a) : public ID3D11DeviceContext1 {
	public:
			virtual HRESULT(UpdateTileMappings)(_In_  ID3D11Resource* pTiledResource,_In_  UINT NumTiledResourceRegions,_In_reads_opt_(NumTiledResourceRegions)  const D3D11_TILED_RESOURCE_COORDINATE* pTiledResourceRegionStartCoordinates,_In_reads_opt_(NumTiledResourceRegions)  const D3D11_TILE_REGION_SIZE* pTiledResourceRegionSizes,_In_opt_  ID3D11Buffer* pTilePool,_In_  UINT NumRanges,_In_reads_opt_(NumRanges)  const UINT* pRangeFlags,_In_reads_opt_(NumRanges)  const UINT* pTilePoolStartOffsets,_In_reads_opt_(NumRanges)  const UINT* pRangeTileCounts,_In_  UINT Flags) = 0;
	virtual HRESULT(CopyTileMappings)(_In_  ID3D11Resource* pDestTiledResource,_In_  const D3D11_TILED_RESOURCE_COORDINATE* pDestRegionStartCoordinate,_In_  ID3D11Resource* pSourceTiledResource,_In_  const D3D11_TILED_RESOURCE_COORDINATE* pSourceRegionStartCoordinate,_In_  const D3D11_TILE_REGION_SIZE* pTileRegionSize,_In_  UINT Flags) = 0;
	virtual void (CopyTiles)(_In_  ID3D11Resource* pTiledResource,_In_  const D3D11_TILED_RESOURCE_COORDINATE* pTileRegionStartCoordinate,_In_  const D3D11_TILE_REGION_SIZE* pTileRegionSize,_In_  ID3D11Buffer* pBuffer,_In_  UINT64 BufferStartOffsetInBytes,_In_  UINT Flags) = 0;
	virtual void (UpdateTiles)(_In_  ID3D11Resource* pDestTiledResource,_In_  const D3D11_TILED_RESOURCE_COORDINATE* pDestTileRegionStartCoordinate,_In_  const D3D11_TILE_REGION_SIZE* pDestTileRegionSize,_In_  const void* pSourceTileData,_In_  UINT Flags) = 0;
	virtual HRESULT(ResizeTilePool)(_In_  ID3D11Buffer* pTilePool,_In_  UINT64 NewSizeInBytes) = 0;
	virtual void (TiledResourceBarrier)(_In_opt_  ID3D11DeviceChild* pTiledResourceOrViewAccessBeforeBarrier,_In_opt_  ID3D11DeviceChild* pTiledResourceOrViewAccessAfterBarrier) = 0;
	};

	// FIXME: handle different versions of the SDK for this class
	D3DINTERFACE(ID3D11DeviceContextX, 48800095, 7134, 4be7, 91, 86, b8, 6b, ec, b2, 64, 77) : public ID3D11DeviceContext2 {
	public:
	virtual INT(PIXBeginEvent)(_In_ LPCWSTR Name) = 0;
	virtual INT(PIXBeginEventEx)(_In_reads_bytes_(DataSize) const void* pData,_In_ UINT DataSize) = 0;
	virtual INT(PIXEndEvent)() = 0;
	virtual void (PIXSetMarker)(_In_ LPCWSTR Name) = 0;
	virtual void (PIXSetMarkerEx)(_In_reads_bytes_(DataSize) const void* pData,_In_ UINT DataSize) = 0;
	virtual BOOL(PIXGetStatus)() = 0;
	virtual HRESULT(PIXGpuCaptureNextFrame)(_In_ UINT Flags,_In_z_ LPCWSTR lpOutputFileName) = 0;
	virtual HRESULT(PIXGpuBeginCapture)(_In_ UINT Flags,_In_z_ LPCWSTR lpOutputFileName) = 0;
	virtual HRESULT(PIXGpuEndCapture)() = 0;
	virtual void (StartCounters)(_In_ ID3D11CounterSetX* pCounterSet) = 0;
	virtual void (SampleCounters)(_In_ ID3D11CounterSampleX* pCounterSample) = 0;
	virtual void (StopCounters)( ) = 0;
	virtual HRESULT(GetCounterData)(_In_ ID3D11CounterSampleX* pCounterSample,_Out_ D3D11X_COUNTER_DATA* pData,_In_ UINT GetCounterDataFlags) = 0;
	virtual void (FlushGpuCaches)(_In_ ID3D11Resource* pResource) = 0;
	virtual void (FlushGpuCacheRange)(_In_ UINT Flags,_In_ void* pBaseAddress,_In_ SIZE_T SizeInBytes) = 0;
	virtual void (InsertWaitUntilIdle)(_In_ UINT Flags) = 0;
	virtual UINT64(InsertFence)(_In_ UINT Flags) = 0;
	virtual void (InsertWaitOnFence)(_In_ UINT Flags,_In_ UINT64 Fence) = 0;
	virtual void (RemapConstantBufferInheritance)(_In_ D3D11_STAGE Stage,_In_ UINT Slot,_In_ D3D11_STAGE InheritStage,_In_ UINT InheritSlot) = 0;
	virtual void (RemapShaderResourceInheritance)(_In_ D3D11_STAGE Stage,_In_ UINT Slot,_In_ D3D11_STAGE InheritStage,_In_ UINT InheritSlot) = 0;
	virtual void (RemapSamplerInheritance)(_In_ D3D11_STAGE Stage,_In_ UINT Slot,_In_ D3D11_STAGE InheritStage,_In_ UINT InheritSlot) = 0;
	virtual void (RemapVertexBufferInheritance)(_In_ UINT Slot,_In_ UINT InheritSlot) = 0;
	virtual void (PSSetFastConstantBuffer)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11Buffer* pConstantBuffer) = 0;
	virtual void (PSSetFastShaderResource)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11ShaderResourceView* pShaderResourceView) = 0;
	virtual void (PSSetFastSampler)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11SamplerState* pSampler) = 0;
	virtual void (VSSetFastConstantBuffer)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11Buffer* pConstantBuffer) = 0;
	virtual void (VSSetFastShaderResource)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11ShaderResourceView* pShaderResourceView) = 0;
	virtual void (VSSetFastSampler)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11SamplerState* pSampler) = 0;
	virtual void (GSSetFastConstantBuffer)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11Buffer* pConstantBuffer) = 0;
	virtual void (GSSetFastShaderResource)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11ShaderResourceView* pShaderResourceView) = 0;
	virtual void (GSSetFastSampler)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11SamplerState* pSampler) = 0;
	virtual void (CSSetFastConstantBuffer)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11Buffer* pConstantBuffer) = 0;
	virtual void (CSSetFastShaderResource)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11ShaderResourceView* pShaderResourceView) = 0;
	virtual void (CSSetFastSampler)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11SamplerState* pSampler) = 0;
	virtual void (HSSetFastConstantBuffer)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11Buffer* pConstantBuffer) = 0;
	virtual void (HSSetFastShaderResource)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11ShaderResourceView* pShaderResourceView) = 0;
	virtual void (HSSetFastSampler)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11SamplerState* pSampler) = 0;
	virtual void (DSSetFastConstantBuffer)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11Buffer* pConstantBuffer) = 0;
	virtual void (DSSetFastShaderResource)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11ShaderResourceView* pShaderResourceView) = 0;
	virtual void (DSSetFastSampler)(_In_range_(0, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11SamplerState* pSampler) = 0;
	virtual void (IASetFastVertexBuffer)(_In_range_(0, D3D11_IA_VERTEX_INPUT_RESOURCE_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11Buffer* pVertexBuffer,_In_ UINT Stride) = 0;
	virtual void (IASetFastIndexBuffer)(_In_ UINT HardwareIndexFormat,_In_ ID3D11Buffer* pIndexBuffer) = 0;
	virtual void (PSSetPlacementConstantBuffer)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11Buffer* pConstantBuffer,_In_ void* pBaseAddress) = 0;
	virtual void (PSSetPlacementShaderResource)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11ShaderResourceView* pShaderResourceView,_In_ void* pBaseAddress) = 0;
	virtual void (VSSetPlacementConstantBuffer)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11Buffer* pConstantBuffer,_In_ void* pBaseAddress) = 0;
	virtual void (VSSetPlacementShaderResource)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11ShaderResourceView* pShaderResourceView,_In_ void* pBaseAddress) = 0;
	virtual void (GSSetPlacementConstantBuffer)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11Buffer* pConstantBuffer,_In_ void* pBaseAddress) = 0;
	virtual void (GSSetPlacementShaderResource)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11ShaderResourceView* pShaderResourceView,_In_ void* pBaseAddress) = 0;
	virtual void (CSSetPlacementConstantBuffer)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11Buffer* pConstantBuffer,_In_ void* pBaseAddress) = 0;
	virtual void (CSSetPlacementShaderResource)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11ShaderResourceView* pShaderResourceView,_In_ void* pBaseAddress) = 0;
	virtual void (HSSetPlacementConstantBuffer)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11Buffer* pConstantBuffer,_In_ void* pBaseAddress) = 0;
	virtual void (HSSetPlacementShaderResource)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11ShaderResourceView* pShaderResourceView,_In_ void* pBaseAddress) = 0;
	virtual void (DSSetPlacementConstantBuffer)(_In_range_(0, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11Buffer* pConstantBuffer,_In_ void* pBaseAddress) = 0;
	virtual void (DSSetPlacementShaderResource)(_In_range_(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11ShaderResourceView* pShaderResourceView,_In_ void* pBaseAddress) = 0;
	virtual void (IASetPlacementVertexBuffer)(_In_range_(0, D3D11_IA_VERTEX_INPUT_RESOURCE_SLOT_COUNT - 1) UINT Slot,_In_ ID3D11Buffer* pVertexBuffer,_In_ void* pBaseAddress,_In_ UINT Stride) = 0;
	virtual void (IASetPlacementIndexBuffer)(_In_ UINT HardwareIndexFormat,_In_ ID3D11Buffer* pIndexBuffer,_In_ void* pBaseAddress) = 0;
	virtual void (HSSetTessellationParameters)(_In_opt_ const D3D11X_TESSELLATION_PARAMETERS* pTessellationParameters) = 0;
	virtual void (HSGetLastUsedTessellationParameters)(_Inout_ D3D11X_TESSELLATION_PARAMETERS* pTessellationParameters) = 0;
	virtual void (CSEnableAutomaticGpuFlush)(_In_ BOOL Enable) = 0;
	virtual void (GpuSendPipelinedEvent)(_In_ D3D11X_GPU_PIPELINED_EVENT Event) = 0;
	virtual HRESULT(Suspend)(_In_ UINT Flags) = 0;
	virtual HRESULT(Resume)() = 0;
	virtual void (BeginCommandListExecution)(_In_ UINT Flags) = 0;
	virtual void (EndCommandListExecution)( ) = 0;
	virtual void (SetGraphicsShaderLimits)(_In_opt_ const D3D11X_GRAPHICS_SHADER_LIMITS* pShaderLimits) = 0;
	virtual void (SetComputeShaderLimits)(_In_opt_ const D3D11X_COMPUTE_SHADER_LIMITS* pShaderLimits) = 0;
	virtual void (SetPredicationBuffer)(_In_opt_ ID3D11Buffer* pBuffer,_In_ UINT Offset,_In_ UINT Flags) = 0;
	virtual void (OMSetDepthBounds)(_In_ FLOAT min,_In_ FLOAT max) = 0;
	virtual void (OMSetDepthStencilStateX)(_In_opt_ ID3D11DepthStencilState* pDepthStencilState) = 0;
	virtual void (OMSetSampleMask)(_In_ UINT64 QuadSampleMask) = 0;
	virtual UINT32* (MakeCeSpace) () = 0;
	virtual void (SetFastResources_Debug)(_In_ UINT* pTableStart,_In_ UINT* pTableEnd) = 0;
	virtual void (BeginResourceBatch)(_Out_ void* pBuffer,_In_ UINT BufferSize) = 0;
	virtual UINT(EndResourceBatch)(_Out_opt_ UINT* pSizeNeeded) = 0;
	virtual void (SetFastResourcesFromBatch_Debug)(_In_ void* pBatch,_In_ UINT Size) = 0; \
	virtual void (CSPlaceUnorderedAccessView)(_In_range_(0, D3D11_1_UAV_SLOT_COUNT - 1) UINT Slot,_In_ D3D11X_DESCRIPTOR_UNORDERED_ACCESS_VIEW* const pDescriptor,_In_ UINT64 Offset) = 0;
	virtual void (WriteValueEndOfPipe)(_In_ void* pDestination,_In_ UINT Value,_In_ UINT Flags) = 0;
	virtual void (CopyMemoryToMemory)(_In_ void* pDstAddress,_In_ void* pSrcAddress,_In_ SIZE_T SizeBytes) = 0;
	virtual void (FillMemoryWithValue)(_In_ void* pDstAddress,_In_ SIZE_T SizeBytes,_In_ UINT FillValue) = 0;
	virtual void (BeginProcessVideoResource)(_In_ ID3D11Resource* pResource,_In_ UINT SubResource) = 0;
	virtual void (EndProcessVideoResource)(_In_ ID3D11Resource* pResource,_In_ UINT SubResource) = 0;
	virtual HRESULT(StartThreadTrace)(_In_ const D3D11X_THREAD_TRACE_DESC* pDesc,_In_ void* pDstAddressShaderEngine0,_In_ void* pDstAddressShaderEngine1,_In_ SIZE_T BufferSizeBytes) = 0;
	virtual void (StopThreadTrace)(_In_ void* pDstAddressTraceSize) = 0;
	virtual void (InsertThreadTraceMarker)(_In_ UINT Marker) = 0;
	virtual void (IASetPrimitiveResetIndex)(_In_ UINT ResetIndex) = 0;
	virtual void (SetShaderResourceViewMinLOD)(_In_ ID3D11ShaderResourceView* pShaderResourceView,FLOAT MinLOD) = 0;
	virtual void (InsertWaitOnPresent)(_In_ UINT Flags,_In_ ID3D11Resource* pBackBuffer) = 0;
	virtual void (ClearRenderTargetViewX)(_In_ ID3D11RenderTargetView* pRenderTargetView,_In_ UINT Flags,_In_ const FLOAT ColorRGBA[ 4 ]) = 0;
	virtual UINT(GetResourceCompression)(_In_ ID3D11Resource* pResource) = 0;
	virtual UINT(GetResourceCompressionX)(_In_ const D3D11X_DESCRIPTOR_RESOURCE* pResource) = 0;
	virtual void (DecompressResource)(_In_ ID3D11Resource* pDstResource,_In_ UINT DstSubresource,_In_opt_ const D3D11X_POINT* pDstPoint,_In_ ID3D11Resource* pSrcResource,_In_ UINT SrcSubresource,_In_opt_ const D3D11X_RECT* pSrcRect,_In_ DXGI_FORMAT DecompressFormat,_In_ UINT DecompressFlags) = 0;
	virtual void (DecompressResourceX)(_In_ D3D11X_DESCRIPTOR_RESOURCE* pDstResource,_In_ UINT DstSubresource,_In_opt_ const D3D11X_POINT* pDstPoint,_In_ D3D11X_DESCRIPTOR_RESOURCE* pSrcResource,_In_ UINT SrcSubresource,_In_opt_ const D3D11X_RECT* pSrcRect,_In_ D3D11X_FORMAT DecompressFormat,_In_ UINT DecompressFlags) = 0;
	virtual void (GSSetParameters)(_In_opt_ const D3D11X_GS_PARAMETERS* pGsParameters) = 0;
	virtual void (GSGetLastUsedParameters)(_Inout_ D3D11X_GS_PARAMETERS* pGsParameters) = 0;
	virtual void (MultiDrawIndexedInstancedIndirect)(_In_ UINT PrimitiveCount,_Inout_ ID3D11Buffer* pBufferForArgs,_In_ UINT AlignedByteOffsetForArgs,_In_ UINT StrideByteOffsetForArgs,_In_ UINT Flags) = 0; \
	virtual void (MultiDrawInstancedIndirect)(_In_ UINT PrimitiveCount,_Inout_ ID3D11Buffer* pBufferForArgs,_In_ UINT AlignedByteOffsetForArgs,_In_ UINT StrideByteOffsetForArgs,_In_ UINT Flags) = 0;
	virtual void (MultiDrawIndexedInstancedIndirectAuto)(_Inout_ ID3D11Buffer* pBufferForPrimitiveCount,_In_ UINT AlignedByteOffsetForPrimitiveCount,_Inout_ ID3D11Buffer* pBufferForArgs,_In_ UINT AlignedByteOffsetForArgs,_In_ UINT StrideByteOffsetForArgs,_In_ UINT Flags) = 0;
	virtual void (MultiDrawInstancedIndirectAuto)(_Inout_ ID3D11Buffer* pBufferForPrimitiveCount,_In_ UINT AlignedByteOffsetForPrimitiveCount,_Inout_ ID3D11Buffer* pBufferForArgs,_In_ UINT AlignedByteOffsetForArgs,_In_ UINT StrideByteOffsetForArgs,_In_ UINT Flags) = 0;
	virtual HRESULT(RSGetMSAASettingsForQuality)(_Inout_opt_ D3D11X_MSAA_SCAN_CONVERTER_SETTINGS* pMSAASCSettings,_Inout_opt_ D3D11X_MSAA_EQAA_SETTINGS* pEQAASettings,_Inout_opt_ D3D11X_MSAA_SAMPLE_PRIORITIES* pCentroidPriorities,_Inout_opt_ D3D11X_MSAA_SAMPLE_POSITIONS* pSamplePositions,_In_ UINT LogSampleCount,_In_ UINT SampleQuality) = 0;
	virtual void (RSSetScanConverterMSAASettings)(_In_ const D3D11X_MSAA_SCAN_CONVERTER_SETTINGS* pMSAASCSettings) = 0;
	virtual void (RSSetEQAASettings)(_In_ const D3D11X_MSAA_EQAA_SETTINGS* pEQAASettings) = 0;
	virtual void (RSSetSamplePositions)(_In_opt_ const D3D11X_MSAA_SAMPLE_PRIORITIES* pSamplesPriorities,_In_opt_ const D3D11X_MSAA_SAMPLE_POSITIONS* pSamplePositions) = 0;
	virtual void (SetResourceCompression)(_In_ ID3D11Resource* pResource,_In_ UINT Compression) = 0;
	virtual void (SetResourceCompressionX)(_In_ const D3D11X_DESCRIPTOR_RESOURCE* pResource,_In_ UINT Compression) = 0;
	virtual void (SetGDSRange)(_In_ D3D11X_GDS_REGION_TYPE RegionType,_In_ UINT OffsetDwords,_In_ UINT NumDwords) = 0;
	virtual void (WriteGDS)(_In_ D3D11X_GDS_REGION_TYPE RegionType,_In_ UINT OffsetDwords,_In_ UINT NumDwords,_In_ const UINT* pCounterValues,_In_ UINT Flags) = 0;
	virtual void (ReadGDS)(_In_ D3D11X_GDS_REGION_TYPE RegionType,_In_ UINT OffsetDwords,_In_ UINT NumDwords,_Inout_ UINT* pCounterValues,_In_ UINT Flags) = 0;
	virtual void (VSSetShaderUserData)(_In_ UINT StartSlot,_In_ UINT NumRegisters,_In_reads_(NumRegisters) const UINT* pData) = 0;
	virtual void (HSSetShaderUserData)(_In_ UINT StartSlot,_In_ UINT NumRegisters,_In_reads_(NumRegisters) const UINT* pData) = 0;
	virtual void (DSSetShaderUserData)(_In_ UINT StartSlot,_In_ UINT NumRegisters,_In_reads_(NumRegisters) const UINT* pData) = 0;
	virtual void (GSSetShaderUserData)(_In_ UINT StartSlot,_In_ UINT NumRegisters,_In_reads_(NumRegisters) const UINT* pData) = 0;
	virtual void (PSSetShaderUserData)(_In_ UINT StartSlot,_In_ UINT NumRegisters,_In_reads_(NumRegisters) const UINT* pData) = 0;
	virtual void (CSSetShaderUserData)(_In_ UINT StartSlot,_In_ UINT NumRegisters,_In_reads_(NumRegisters) const UINT* pData) = 0;
	virtual void (InsertWaitOnMemory)(_In_ const void* pAddress,_In_ UINT Flags,_In_ D3D11_COMPARISON_FUNC ComparisonFunction,_In_ UINT ReferenceValue,_In_ UINT Mask) = 0;
	virtual void (WriteTimestampToMemory)(_In_ void* pDstAddress) = 0;
	virtual void (WriteTimestampToBuffer)(_In_ ID3D11Buffer* pBuffer,_In_ UINT OffsetBytes) = 0;
	virtual void (StoreConstantRam)(_In_ UINT Flags,_In_ ID3D11Buffer* pBuffer,_In_ UINT BufferOffsetInBytes,_In_ UINT CeRamOffsetInBytes,_In_ UINT SizeInBytes) = 0;
	virtual void (LoadConstantRam)(_In_ UINT Flags,_In_ ID3D11Buffer* pBuffer,_In_ UINT BufferOffsetInBytes,_In_ UINT CeRamOffsetInBytes,_In_ UINT SizeInBytes) = 0;
	virtual void (WriteQuery)(_In_ D3D11_QUERY QueryType,_In_ UINT QueryIndex,_In_ UINT Flags,_In_ ID3D11Buffer* pBuffer,_In_ UINT OffsetInBytes,_In_ UINT StrideInBytes) = 0;
	virtual void (ResetQuery)(_In_ D3D11_QUERY QueryType,_In_ UINT QueryIndex,_In_ UINT Flags) = 0;
	virtual void (ConfigureQuery)(_In_ D3D11_QUERY QueryType,_In_ const void* pConfiguration,_In_ UINT ConfigurationSize) = 0;
	virtual void (SetShaderUserData)(_In_ D3D11X_HW_STAGE ShaderStage,_In_ UINT StartSlot,_In_ UINT NumRegisters,_In_reads_(NumRegisters) const UINT* pData) = 0;
	virtual void (SetPixelShaderDepthForceZOrder)(_In_ BOOL ForceOrder) = 0;
	virtual void (SetPredicationFromQuery)(_In_ D3D11_QUERY QueryType,_In_ ID3D11Buffer* pBuffer,_In_ UINT OffsetInBytes,_In_ UINT Flags) = 0;
	virtual void (SetBorderColorPalette)(_In_ ID3D11Buffer* pBuffer,_In_ UINT OffsetInBytes,_In_ UINT Flags) = 0;
	virtual void (WriteValueEndOfPipe64)(_In_ void* pDestination,_In_ UINT64 Value,_In_ UINT Flags) = 0;
	virtual void (InsertWaitOnMemory64)(_In_ const void* pAddress,_In_ UINT Flags,_In_ D3D11_COMPARISON_FUNC ComparisonFunction,_In_ UINT64 ReferenceValue) = 0;
	virtual void (LoadConstantRamImmediate)(_In_ UINT Flags,_In_ const void* pBuffer,_In_ UINT CeRamOffsetInBytes,_In_ UINT SizeInBytes) = 0;
	virtual void (SetScreenExtentsQuery)(_In_ UINT Value) = 0;
	virtual void (CollectScreenExtents)(_In_ UINT Flags,_In_ UINT AddressCount,_In_reads_(AddressCount) const UINT64* pDestinationAddresses,_In_ USHORT ZMin,_In_ USHORT ZMax) = 0;
	virtual void (FillResourceWithValue)(_In_ ID3D11Resource* pDstResource,_In_ UINT FillValue) = 0;
	virtual void (SetDrawBalancing)(_In_ UINT BalancingMode,_In_ UINT Flags) = 0;
	};

	D3DINTERFACE(ID3D11UserDefinedAnnotationX, b2daad8b, 03d4, 4dbf, 95, eb, 32, ab, 4b, 63, d0, ab) {

	};

	D3DINTERFACE(ID3D11PerformanceContextX, 9458FE06, C78D, 47F7, 96, A0, EC, 7B, 72, 7B, E1, E9) : public ID3D11DeviceContextX{};


}

namespace wd
{
	struct D3D11XShaderUserDataManagerDraw
	{
		// Dirty flags are used for state that is handled by D3D in a deferred fashion at 
		// Draw/Dispatch time. Flags use the D3D11X_DIRTYFLAGS enumerant.
		UINT32 m_DirtyFlags;

		// Reserved.
		UINT32 m_Reserved1;

		// Hardware encoded primitive topology:
		UINT64 m_Topology;

		// Pointer to the currently set input layout (if any):
		ID3D11InputLayout* m_pInputLayout;

		// Pointer to the currently set vertex shader (if any):
		ID3D11VertexShader* m_pVs;

		// Pointer to the currently set pixel shader (if any):
		ID3D11PixelShader* m_pPs;

		// Reserved space:
		UINT32 m_Reserved2[ 128 ];
	};

	struct D3D11XTinyDevice
	{
		// Number of dwords by which pCeBiasedLimit is biased downward from the true limit:
		static const UINT32 BiasDwordCount = 70;

		// Minimum number of dwords that is available after calling MakeCeSpace:
		static const UINT32 MakeCeSpaceDwordCount = 1024;

		// Reserved space:
		UINT32 m_Reserved1[ 8 ];

		// Points to the current location in the resource batch being recorded:
		UINT32* m_pBatchCurrent;

		// Points to the end of the writable batch buffer:
		UINT32* m_pBatchLimit;

		// Points to the location in the indirect buffer or command list currently being constructed 
		// where the next GPU Constant Engine command will be added:
		UINT32* m_pCeCurrent;

		// Points to the end of the current Constant Engine segment biased down by BiasDwordCount dwords. 
		// If pCeRing <= pCeBiasedLimit then it's guaranteed that there are at least 64 dwords
		// of room left in the ring buffer. If pCeRing > pCeBiasedLimit then MakeCeSpace() must be
		// called before any more data can be added:
		UINT32* m_pCeBiasedLimit;

		// Points to the end of the current Constant Engine segment with no bias:
		UINT32* m_pCeLimit;

		// Reserved space:
		UINT32 m_Reserved2[ 64 ];
	};

	class device_context_x : public wdi::ID3D11DeviceContextX
	{
	public:
		device_context_x(::ID3D11DeviceContext2* wrapped_interface) : wrapped_interface(wrapped_interface)
		{
			populate_function_tables( );
			wrapped_interface->AddRef( );
		}

	private:
		// even though these don't conform to our naming convention, we keep them b/c their origin
		D3D11XTinyDevice m_TinyDevice;
		D3D11XShaderUserDataManagerDraw m_ShaderUserDataManagerDraw;

		union
		{
			uint8_t m_OutOfLineFlags;
			uint32_t m_Reserved[ 16 ];
		} DUMMYUNIONNAME;

		std::array<FARPROC, 270> function_table;

		void populate_function_tables( )
		{
			auto v_ptr = *reinterpret_cast<FARPROC**>(this);

			for (size_t i = 0; i < function_table.size( ); i++)
				function_table[ i ] = v_ptr[ i ];
		}

		IGU_DEFINE_REF

		HRESULT QueryInterface(const IID& riid, void** ppvObject) override
		{
			if (riid == __uuidof(wdi::ID3D11DeviceContext) || riid == __uuidof(wdi::ID3D11DeviceContext1) ||
				riid == __uuidof(wdi::ID3D11DeviceContext2) || riid == __uuidof(wdi::ID3D11DeviceContextX) ||
				riid == __uuidof(wdi::ID3D11UserDefinedAnnotationX) || riid == __uuidof(wdi::ID3D11PerformanceContextX))
			{
				*ppvObject = this;
				AddRef( );
				return S_OK;
			}

			if (riid == __uuidof(wdi::IGraphicsUnwrap))
			{
				*ppvObject = wrapped_interface;
				return S_OK;
			}

			TRACE_INTERFACE_NOT_HANDLED("device_context_x");
			*ppvObject = nullptr;
			return E_NOINTERFACE;
		}

		void GetDevice(ID3D11Device** ppDevice) override;
		HRESULT GetPrivateData(const GUID& guid, UINT* pDataSize, void* pData) override;
		HRESULT SetPrivateData(const GUID& guid, UINT DataSize, const void* pData) override;
		HRESULT SetPrivateDataInterface(const GUID& guid, const IUnknown* pData) override;
		HRESULT SetPrivateDataInterfaceGraphics(const GUID& guid, const IGraphicsUnknown* pData) override;
		HRESULT SetName(LPCWSTR pName) override;

	public:
		void ProcessDirtyFlags()
		{
			// 0x46 = topology dirty flag
			if (m_ShaderUserDataManagerDraw.m_DirtyFlags & 0x46)
			{
				m_ShaderUserDataManagerDraw.m_DirtyFlags &= ~0x46;
				int topology = D3D11X_HARDWARE_TO_TOPOLOGY_MAP.at(m_ShaderUserDataManagerDraw.m_Topology);
				if (topology == 6 || topology == 17 || topology == 18 || topology == 19 || topology == 20)
					printf("WARN: device_context_x::ProcessDirtyFlags: unsupported topology %d\n", topology);

				wrapped_interface->IASetPrimitiveTopology(static_cast<D3D11_PRIMITIVE_TOPOLOGY>(topology));
			}

			// 0x89 = input layout dirty flag
			if (m_ShaderUserDataManagerDraw.m_DirtyFlags & 0x89)
			{
				m_ShaderUserDataManagerDraw.m_DirtyFlags &= ~0x89;
				wrapped_interface->IASetInputLayout(m_ShaderUserDataManagerDraw.m_pInputLayout);
			}

			// 0x91 = vertex shader dirty flag
			if (m_ShaderUserDataManagerDraw.m_DirtyFlags & 0x91)
			{
				m_ShaderUserDataManagerDraw.m_DirtyFlags &= ~0x91;
				wrapped_interface->VSSetShader(m_ShaderUserDataManagerDraw.m_pVs, nullptr, 0);
			}

			// 0x121 = pixel shader dirty flag
			if (m_ShaderUserDataManagerDraw.m_DirtyFlags & 0x121)
			{
				m_ShaderUserDataManagerDraw.m_DirtyFlags &= ~0x121;
				wrapped_interface->PSSetShader(m_ShaderUserDataManagerDraw.m_pPs, nullptr, 0);
			}
		}

		void VSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override;
		void Draw(UINT VertexCount, UINT StartVertexLocation) override;
		HRESULT Map(ID3D11Resource* pResource, UINT Subresource, D3D11_MAP MapType, UINT MapFlags,
			D3D11_MAPPED_SUBRESOURCE* pMappedResource) override;
		void Unmap(ID3D11Resource* pResource, UINT Subresource) override;
		void PSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override;
		void IASetInputLayout(ID3D11InputLayout* pInputLayout) override;
		void IASetVertexBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppVertexBuffers,
			const UINT* pStrides, const UINT* pOffsets) override;
		void VSSetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState* const* ppSamplers) override;
		void Begin(ID3D11Asynchronous* pAsync) override;
		void End(ID3D11Asynchronous* pAsync) override;
		HRESULT GetData(ID3D11Asynchronous* pAsync, void* pData, UINT DataSize, UINT GetDataFlags) override;
		void SetPredication(ID3D11Predicate* pPredicate, BOOL PredicateValue) override;
		void GSSetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState* const* ppSamplers) override;
		void OMSetRenderTargets(UINT NumViews, ID3D11RenderTargetView* const* ppRenderTargetViews,
			ID3D11DepthStencilView* pDepthStencilView) override;
		void OMSetRenderTargetsAndUnorderedAccessViews(UINT NumRTVs, ID3D11RenderTargetView* const* ppRenderTargetViews,
			ID3D11DepthStencilView* pDepthStencilView, UINT UAVStartSlot, UINT NumUAVs,
			ID3D11UnorderedAccessView* const* ppUnorderedAccessViews, const UINT* pUAVInitialCounts) override;
		void OMSetBlendState(ID3D11BlendState* pBlendState, const FLOAT BlendFactor[4], UINT SampleMask) override;
		void OMSetDepthStencilState(ID3D11DepthStencilState* pDepthStencilState, UINT StencilRef) override;
		void SOSetTargets(UINT NumBuffers, ID3D11Buffer* const* ppSOTargets, const UINT* pOffsets) override;
		void DrawIndexedInstancedIndirect(ID3D11Buffer* pBufferForArgs, UINT AlignedByteOffsetForArgs) override;
		void DrawInstancedIndirect(ID3D11Buffer* pBufferForArgs, UINT AlignedByteOffsetForArgs) override;
		void Dispatch(UINT ThreadGroupCountX, UINT ThreadGroupCountY, UINT ThreadGroupCountZ) override;
		void DispatchIndirect(ID3D11Buffer* pBufferForArgs, UINT AlignedByteOffsetForArgs) override;
		void RSSetState(ID3D11RasterizerState* pRasterizerState) override;
		void RSSetViewports(UINT NumViewports, const D3D11_VIEWPORT* pViewports) override;
		void RSSetScissorRects(UINT NumRects, const D3D11_RECT* pRects) override;
		void CopySubresourceRegion(ID3D11Resource* pDstResource, UINT DstSubresource, UINT DstX, UINT DstY, UINT DstZ,
			ID3D11Resource* pSrcResource, UINT SrcSubresource, const D3D11_BOX* pSrcBox) override;
		void CopyResource(ID3D11Resource* pDstResource, ID3D11Resource* pSrcResource) override;
		void UpdateSubresource(ID3D11Resource* pDstResource, UINT DstSubresource, const D3D11_BOX* pDstBox,
			const void* pSrcData, UINT SrcRowPitch, UINT SrcDepthPitch) override;
		void CopyStructureCount(ID3D11Buffer* pDstBuffer, UINT DstAlignedByteOffset,
			ID3D11UnorderedAccessView* pSrcView) override;
		void ClearRenderTargetView(ID3D11RenderTargetView* pRenderTargetView, const FLOAT ColorRGBA[4]) override;
		void ClearUnorderedAccessViewUint(ID3D11UnorderedAccessView* pUnorderedAccessView,
			const UINT Values[4]) override;
		void ClearUnorderedAccessViewFloat(ID3D11UnorderedAccessView* pUnorderedAccessView,
			const FLOAT Values[4]) override;
		void ClearDepthStencilView(ID3D11DepthStencilView* pDepthStencilView, UINT ClearFlags, FLOAT Depth,
			UINT8 Stencil) override;
		void GenerateMips(ID3D11ShaderResourceView* pShaderResourceView) override;
		void SetResourceMinLOD(ID3D11Resource* pResource, FLOAT MinLOD) override;
		FLOAT GetResourceMinLOD(ID3D11Resource* pResource) override;
		void ResolveSubresource(ID3D11Resource* pDstResource, UINT DstSubresource, ID3D11Resource* pSrcResource,
			UINT SrcSubresource, DXGI_FORMAT Format) override;
		void ExecuteCommandList(ID3D11CommandList* pCommandList, BOOL RestoreContextState) override;
		void HSSetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState* const* ppSamplers) override;
		void HSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override;
		void DSSetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState* const* ppSamplers) override;
		void DSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override;
		void CSSetUnorderedAccessViews(UINT StartSlot, UINT NumUAVs,
			ID3D11UnorderedAccessView* const* ppUnorderedAccessViews, const UINT* pUAVInitialCounts) override;
		void CSSetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState* const* ppSamplers) override;
		void CSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override;
		void VSGetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers) override;
		void PSGetShaderResources(UINT StartSlot, UINT NumViews,
			ID3D11ShaderResourceView** ppShaderResourceViews) override;
		void PSGetShader(ID3D11PixelShader** ppPixelShader, ID3D11ClassInstance** ppClassInstances,
			UINT* pNumClassInstances) override;
		void PSGetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState** ppSamplers) override;
		void VSGetShader(ID3D11VertexShader** ppVertexShader, ID3D11ClassInstance** ppClassInstances,
			UINT* pNumClassInstances) override;
		void PSGetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers) override;
		void IAGetInputLayout(ID3D11InputLayout** ppInputLayout) override;
		void IAGetVertexBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppVertexBuffers, UINT* pStrides,
			UINT* pOffsets) override;
		void IAGetIndexBuffer(ID3D11Buffer** pIndexBuffer, DXGI_FORMAT* Format, UINT* Offset) override;
		void GSGetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers) override;
		void GSGetShader(ID3D11GeometryShader** ppGeometryShader, ID3D11ClassInstance** ppClassInstances,
			UINT* pNumClassInstances) override;
		void IAGetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY* pTopology) override;
		void VSGetShaderResources(UINT StartSlot, UINT NumViews,
			ID3D11ShaderResourceView** ppShaderResourceViews) override;
		void VSGetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState** ppSamplers) override;
		void GetPredication(ID3D11Predicate** ppPredicate, BOOL* pPredicateValue) override;
		void GSGetShaderResources(UINT StartSlot, UINT NumViews,
			ID3D11ShaderResourceView** ppShaderResourceViews) override;
		void GSGetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState** ppSamplers) override;
		void OMGetRenderTargets(UINT NumViews, ID3D11RenderTargetView** ppRenderTargetViews,
			ID3D11DepthStencilView** ppDepthStencilView) override;
		void OMGetRenderTargetsAndUnorderedAccessViews(UINT NumRTVs, ID3D11RenderTargetView** ppRenderTargetViews,
			ID3D11DepthStencilView** ppDepthStencilView, UINT UAVStartSlot, UINT NumUAVs,
			ID3D11UnorderedAccessView** ppUnorderedAccessViews) override;
		void OMGetBlendState(ID3D11BlendState** ppBlendState, FLOAT BlendFactor[4], UINT* pSampleMask) override;
		void OMGetDepthStencilState(ID3D11DepthStencilState** ppDepthStencilState, UINT* pStencilRef) override;
		void SOGetTargets(UINT NumBuffers, ID3D11Buffer** ppSOTargets) override;
		void RSGetState(ID3D11RasterizerState** ppRasterizerState) override;
		void RSGetViewports(UINT* pNumViewports, D3D11_VIEWPORT* pViewports) override;
		void RSGetScissorRects(UINT* pNumRects, D3D11_RECT* pRects) override;
		void HSGetShaderResources(UINT StartSlot, UINT NumViews,
			ID3D11ShaderResourceView** ppShaderResourceViews) override;
		void HSGetShader(ID3D11HullShader** ppHullShader, ID3D11ClassInstance** ppClassInstances,
			UINT* pNumClassInstances) override;
		void HSGetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState** ppSamplers) override;
		void HSGetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers) override;
		void DSGetShaderResources(UINT StartSlot, UINT NumViews,
			ID3D11ShaderResourceView** ppShaderResourceViews) override;
		void DSGetShader(ID3D11DomainShader** ppDomainShader, ID3D11ClassInstance** ppClassInstances,
			UINT* pNumClassInstances) override;
		void DSGetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState** ppSamplers) override;
		void DSGetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers) override;
		void CSGetShaderResources(UINT StartSlot, UINT NumViews,
			ID3D11ShaderResourceView** ppShaderResourceViews) override;
		void CSGetUnorderedAccessViews(UINT StartSlot, UINT NumUAVs,
			ID3D11UnorderedAccessView** ppUnorderedAccessViews) override;
		void CSGetShader(ID3D11ComputeShader** ppComputeShader, ID3D11ClassInstance** ppClassInstances,
			UINT* pNumClassInstances) override;
		void CSGetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState** ppSamplers) override;
		void CSGetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers) override;
		void ClearState() override;
		void Flush() override;
		D3D11_DEVICE_CONTEXT_TYPE GetType() override;
		UINT GetContextFlags() override;
		HRESULT FinishCommandList(BOOL RestoreDeferredContextState, ID3D11CommandList** ppCommandList) override;
		void CopySubresourceRegion1(ID3D11Resource* pDstResource, UINT DstSubresource, UINT DstX, UINT DstY, UINT DstZ,
			ID3D11Resource* pSrcResource, UINT SrcSubresource, const D3D11_BOX* pSrcBox, UINT CopyFlags) override;
		void UpdateSubresource1(ID3D11Resource* pDstResource, UINT DstSubresource, const D3D11_BOX* pDstBox,
			const void* pSrcData, UINT SrcRowPitch, UINT SrcDepthPitch, UINT CopyFlags) override;
		void DiscardResource(ID3D11Resource* pResource) override;
		void DiscardView(ID3D11View* pResourceView) override;
		void VSSetConstantBuffers1(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers,
			const UINT* pFirstConstant, const UINT* pNumConstants) override;
		void HSSetConstantBuffers1(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers,
			const UINT* pFirstConstant, const UINT* pNumConstants) override;
		void DSSetConstantBuffers1(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers,
			const UINT* pFirstConstant, const UINT* pNumConstants) override;
		void GSSetConstantBuffers1(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers,
			const UINT* pFirstConstant, const UINT* pNumConstants) override;
		void PSSetConstantBuffers1(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers,
			const UINT* pFirstConstant, const UINT* pNumConstants) override;
		void CSSetConstantBuffers1(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers,
			const UINT* pFirstConstant, const UINT* pNumConstants) override;
		void VSGetConstantBuffers1(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers,
			UINT* pFirstConstant, UINT* pNumConstants) override;
		void HSGetConstantBuffers1(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers,
			UINT* pFirstConstant, UINT* pNumConstants) override;
		void DSGetConstantBuffers1(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers,
			UINT* pFirstConstant, UINT* pNumConstants) override;
		void GSGetConstantBuffers1(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers,
			UINT* pFirstConstant, UINT* pNumConstants) override;
		void PSGetConstantBuffers1(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers,
			UINT* pFirstConstant, UINT* pNumConstants) override;
		void CSGetConstantBuffers1(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers,
			UINT* pFirstConstant, UINT* pNumConstants) override;
		void SwapDeviceContextState(ID3DDeviceContextState* pState, ID3DDeviceContextState** ppPreviousState) override;
		void ClearView(ID3D11View* pView, const FLOAT Color[4], const D3D11_RECT* pRect, UINT NumRects) override;
		void DiscardView1(ID3D11View* pResourceView, const D3D11_RECT* pRects, UINT NumRects) override;
		HRESULT UpdateTileMappings(ID3D11Resource* pTiledResource, UINT NumTiledResourceRegions,
			const D3D11_TILED_RESOURCE_COORDINATE* pTiledResourceRegionStartCoordinates,
			const D3D11_TILE_REGION_SIZE* pTiledResourceRegionSizes, ID3D11Buffer* pTilePool, UINT NumRanges,
			const UINT* pRangeFlags, const UINT* pTilePoolStartOffsets, const UINT* pRangeTileCounts,
			UINT Flags) override;
		HRESULT CopyTileMappings(ID3D11Resource* pDestTiledResource,
			const D3D11_TILED_RESOURCE_COORDINATE* pDestRegionStartCoordinate, ID3D11Resource* pSourceTiledResource,
			const D3D11_TILED_RESOURCE_COORDINATE* pSourceRegionStartCoordinate,
			const D3D11_TILE_REGION_SIZE* pTileRegionSize, UINT Flags) override;
		void CopyTiles(ID3D11Resource* pTiledResource,
			const D3D11_TILED_RESOURCE_COORDINATE* pTileRegionStartCoordinate,
			const D3D11_TILE_REGION_SIZE* pTileRegionSize, ID3D11Buffer* pBuffer, UINT64 BufferStartOffsetInBytes,
			UINT Flags) override;
		void UpdateTiles(ID3D11Resource* pDestTiledResource,
			const D3D11_TILED_RESOURCE_COORDINATE* pDestTileRegionStartCoordinate,
			const D3D11_TILE_REGION_SIZE* pDestTileRegionSize, const void* pSourceTileData, UINT Flags) override;
		HRESULT ResizeTilePool(ID3D11Buffer* pTilePool, UINT64 NewSizeInBytes) override;
		void TiledResourceBarrier(ID3D11DeviceChild* pTiledResourceOrViewAccessBeforeBarrier,
			ID3D11DeviceChild* pTiledResourceOrViewAccessAfterBarrier) override;
		INT PIXBeginEvent(LPCWSTR Name) override;
		INT PIXBeginEventEx(const void* pData, UINT DataSize) override;
		INT PIXEndEvent() override;
		void PIXSetMarker(LPCWSTR Name) override;
		void PIXSetMarkerEx(const void* pData, UINT DataSize) override;
		BOOL PIXGetStatus() override;
		HRESULT PIXGpuCaptureNextFrame(UINT Flags, LPCWSTR lpOutputFileName) override;
		HRESULT PIXGpuBeginCapture(UINT Flags, LPCWSTR lpOutputFileName) override;
		HRESULT PIXGpuEndCapture() override;
		void StartCounters(wdi::ID3D11CounterSetX* pCounterSet) override;
		void SampleCounters(wdi::ID3D11CounterSampleX* pCounterSample) override;
		void StopCounters() override;
		HRESULT GetCounterData(wdi::ID3D11CounterSampleX* pCounterSample, wdi::D3D11X_COUNTER_DATA* pData,
			UINT GetCounterDataFlags) override;
		void FlushGpuCaches(ID3D11Resource* pResource) override;
		void FlushGpuCacheRange(UINT Flags, void* pBaseAddress, SIZE_T SizeInBytes) override;
		void InsertWaitUntilIdle(UINT Flags) override;
		UINT64 InsertFence(UINT Flags) override;
		void InsertWaitOnFence(UINT Flags, UINT64 Fence) override;
		void RemapConstantBufferInheritance(wdi::D3D11_STAGE Stage, UINT Slot, wdi::D3D11_STAGE InheritStage,
			UINT InheritSlot) override;
		void RemapShaderResourceInheritance(wdi::D3D11_STAGE Stage, UINT Slot, wdi::D3D11_STAGE InheritStage,
			UINT InheritSlot) override;
		void RemapSamplerInheritance(wdi::D3D11_STAGE Stage, UINT Slot, wdi::D3D11_STAGE InheritStage,
			UINT InheritSlot) override;
		void RemapVertexBufferInheritance(UINT Slot, UINT InheritSlot) override;
		void PSSetFastConstantBuffer(UINT Slot, ID3D11Buffer* pConstantBuffer) override;
		void PSSetFastShaderResource(UINT Slot, ID3D11ShaderResourceView* pShaderResourceView) override;
		void PSSetFastSampler(UINT Slot, ID3D11SamplerState* pSampler) override;
		void VSSetFastConstantBuffer(UINT Slot, ID3D11Buffer* pConstantBuffer) override;
		void VSSetFastShaderResource(UINT Slot, ID3D11ShaderResourceView* pShaderResourceView) override;
		void VSSetFastSampler(UINT Slot, ID3D11SamplerState* pSampler) override;
		void GSSetFastConstantBuffer(UINT Slot, ID3D11Buffer* pConstantBuffer) override;
		void GSSetFastShaderResource(UINT Slot, ID3D11ShaderResourceView* pShaderResourceView) override;
		void GSSetFastSampler(UINT Slot, ID3D11SamplerState* pSampler) override;
		void CSSetFastConstantBuffer(UINT Slot, ID3D11Buffer* pConstantBuffer) override;
		void CSSetFastShaderResource(UINT Slot, ID3D11ShaderResourceView* pShaderResourceView) override;
		void CSSetFastSampler(UINT Slot, ID3D11SamplerState* pSampler) override;
		void HSSetFastConstantBuffer(UINT Slot, ID3D11Buffer* pConstantBuffer) override;
		void HSSetFastShaderResource(UINT Slot, ID3D11ShaderResourceView* pShaderResourceView) override;
		void HSSetFastSampler(UINT Slot, ID3D11SamplerState* pSampler) override;
		void DSSetFastConstantBuffer(UINT Slot, ID3D11Buffer* pConstantBuffer) override;
		void DSSetFastShaderResource(UINT Slot, ID3D11ShaderResourceView* pShaderResourceView) override;
		void DSSetFastSampler(UINT Slot, ID3D11SamplerState* pSampler) override;
		void IASetFastVertexBuffer(UINT Slot, ID3D11Buffer* pVertexBuffer, UINT Stride) override;
		void IASetFastIndexBuffer(UINT HardwareIndexFormat, ID3D11Buffer* pIndexBuffer) override;
		void PSSetPlacementConstantBuffer(UINT Slot, ID3D11Buffer* pConstantBuffer, void* pBaseAddress) override;
		void PSSetPlacementShaderResource(UINT Slot, ID3D11ShaderResourceView* pShaderResourceView,
			void* pBaseAddress) override;
		void VSSetPlacementConstantBuffer(UINT Slot, ID3D11Buffer* pConstantBuffer, void* pBaseAddress) override;
		void VSSetPlacementShaderResource(UINT Slot, ID3D11ShaderResourceView* pShaderResourceView,
			void* pBaseAddress) override;
		void GSSetPlacementConstantBuffer(UINT Slot, ID3D11Buffer* pConstantBuffer, void* pBaseAddress) override;
		void GSSetPlacementShaderResource(UINT Slot, ID3D11ShaderResourceView* pShaderResourceView,
			void* pBaseAddress) override;
		void CSSetPlacementConstantBuffer(UINT Slot, ID3D11Buffer* pConstantBuffer, void* pBaseAddress) override;
		void CSSetPlacementShaderResource(UINT Slot, ID3D11ShaderResourceView* pShaderResourceView,
			void* pBaseAddress) override;
		void HSSetPlacementConstantBuffer(UINT Slot, ID3D11Buffer* pConstantBuffer, void* pBaseAddress) override;
		void HSSetPlacementShaderResource(UINT Slot, ID3D11ShaderResourceView* pShaderResourceView,
			void* pBaseAddress) override;
		void DSSetPlacementConstantBuffer(UINT Slot, ID3D11Buffer* pConstantBuffer, void* pBaseAddress) override;
		void DSSetPlacementShaderResource(UINT Slot, ID3D11ShaderResourceView* pShaderResourceView,
			void* pBaseAddress) override;
		void IASetPlacementVertexBuffer(UINT Slot, ID3D11Buffer* pVertexBuffer, void* pBaseAddress,
			UINT Stride) override;
		void IASetPlacementIndexBuffer(UINT HardwareIndexFormat, ID3D11Buffer* pIndexBuffer,
			void* pBaseAddress) override;
		void HSSetTessellationParameters(const wdi::D3D11X_TESSELLATION_PARAMETERS* pTessellationParameters) override;
		void HSGetLastUsedTessellationParameters(wdi::D3D11X_TESSELLATION_PARAMETERS* pTessellationParameters) override;
		void CSEnableAutomaticGpuFlush(BOOL Enable) override;
		void GpuSendPipelinedEvent(wdi::D3D11X_GPU_PIPELINED_EVENT Event) override;
		HRESULT Suspend(UINT Flags) override;
		HRESULT Resume() override;
		void BeginCommandListExecution(UINT Flags) override;
		void EndCommandListExecution() override;
		void SetGraphicsShaderLimits(const wdi::D3D11X_GRAPHICS_SHADER_LIMITS* pShaderLimits) override;
		void SetComputeShaderLimits(const wdi::D3D11X_COMPUTE_SHADER_LIMITS* pShaderLimits) override;
		void SetPredicationBuffer(ID3D11Buffer* pBuffer, UINT Offset, UINT Flags) override;
		void OMSetDepthBounds(FLOAT min, FLOAT max) override;
		void OMSetDepthStencilStateX(ID3D11DepthStencilState* pDepthStencilState) override;
		void OMSetSampleMask(UINT64 QuadSampleMask) override;
		UINT32* MakeCeSpace() override;
		void SetFastResources_Debug(UINT* pTableStart, UINT* pTableEnd) override;
		void BeginResourceBatch(void* pBuffer, UINT BufferSize) override;
		UINT EndResourceBatch(UINT* pSizeNeeded) override;
		void SetFastResourcesFromBatch_Debug(void* pBatch, UINT Size) override;
		void CSPlaceUnorderedAccessView(UINT Slot, wdi::D3D11X_DESCRIPTOR_UNORDERED_ACCESS_VIEW* const pDescriptor,
			UINT64 Offset) override;
		void WriteValueEndOfPipe(void* pDestination, UINT Value, UINT Flags) override;
		void CopyMemoryToMemory(void* pDstAddress, void* pSrcAddress, SIZE_T SizeBytes) override;
		void FillMemoryWithValue(void* pDstAddress, SIZE_T SizeBytes, UINT FillValue) override;
		void BeginProcessVideoResource(ID3D11Resource* pResource, UINT SubResource) override;
		void EndProcessVideoResource(ID3D11Resource* pResource, UINT SubResource) override;
		HRESULT StartThreadTrace(const wdi::D3D11X_THREAD_TRACE_DESC* pDesc, void* pDstAddressShaderEngine0,
			void* pDstAddressShaderEngine1, SIZE_T BufferSizeBytes) override;
		void StopThreadTrace(void* pDstAddressTraceSize) override;
		void InsertThreadTraceMarker(UINT Marker) override;
		void IASetPrimitiveResetIndex(UINT ResetIndex) override;
		void SetShaderResourceViewMinLOD(ID3D11ShaderResourceView* pShaderResourceView, FLOAT MinLOD) override;
		void InsertWaitOnPresent(UINT Flags, ID3D11Resource* pBackBuffer) override;
		void ClearRenderTargetViewX(ID3D11RenderTargetView* pRenderTargetView, UINT Flags,
			const FLOAT ColorRGBA[4]) override;
		UINT GetResourceCompression(ID3D11Resource* pResource) override;
		UINT GetResourceCompressionX(const wdi::D3D11X_DESCRIPTOR_RESOURCE* pResource) override;
		void DecompressResource(ID3D11Resource* pDstResource, UINT DstSubresource, const wdi::D3D11X_POINT* pDstPoint,
			ID3D11Resource* pSrcResource, UINT SrcSubresource, const wdi::D3D11X_RECT* pSrcRect,
			DXGI_FORMAT DecompressFormat, UINT DecompressFlags) override;
		void DecompressResourceX(wdi::D3D11X_DESCRIPTOR_RESOURCE* pDstResource, UINT DstSubresource,
			const wdi::D3D11X_POINT* pDstPoint, wdi::D3D11X_DESCRIPTOR_RESOURCE* pSrcResource, UINT SrcSubresource,
			const wdi::D3D11X_RECT* pSrcRect, wdi::D3D11X_FORMAT DecompressFormat, UINT DecompressFlags) override;
		void GSSetParameters(const wdi::D3D11X_GS_PARAMETERS* pGsParameters) override;
		void GSGetLastUsedParameters(wdi::D3D11X_GS_PARAMETERS* pGsParameters) override;
		void MultiDrawIndexedInstancedIndirect(UINT PrimitiveCount, ID3D11Buffer* pBufferForArgs,
			UINT AlignedByteOffsetForArgs, UINT StrideByteOffsetForArgs, UINT Flags) override;
		void MultiDrawInstancedIndirect(UINT PrimitiveCount, ID3D11Buffer* pBufferForArgs,
			UINT AlignedByteOffsetForArgs, UINT StrideByteOffsetForArgs, UINT Flags) override;
		void MultiDrawIndexedInstancedIndirectAuto(ID3D11Buffer* pBufferForPrimitiveCount,
			UINT AlignedByteOffsetForPrimitiveCount, ID3D11Buffer* pBufferForArgs, UINT AlignedByteOffsetForArgs,
			UINT StrideByteOffsetForArgs, UINT Flags) override;
		void MultiDrawInstancedIndirectAuto(ID3D11Buffer* pBufferForPrimitiveCount,
			UINT AlignedByteOffsetForPrimitiveCount, ID3D11Buffer* pBufferForArgs, UINT AlignedByteOffsetForArgs,
			UINT StrideByteOffsetForArgs, UINT Flags) override;
		HRESULT RSGetMSAASettingsForQuality(wdi::D3D11X_MSAA_SCAN_CONVERTER_SETTINGS* pMSAASCSettings,
			wdi::D3D11X_MSAA_EQAA_SETTINGS* pEQAASettings, wdi::D3D11X_MSAA_SAMPLE_PRIORITIES* pCentroidPriorities,
			wdi::D3D11X_MSAA_SAMPLE_POSITIONS* pSamplePositions, UINT LogSampleCount, UINT SampleQuality) override;
		void RSSetScanConverterMSAASettings(const wdi::D3D11X_MSAA_SCAN_CONVERTER_SETTINGS* pMSAASCSettings) override;
		void RSSetEQAASettings(const wdi::D3D11X_MSAA_EQAA_SETTINGS* pEQAASettings) override;
		void RSSetSamplePositions(const wdi::D3D11X_MSAA_SAMPLE_PRIORITIES* pSamplesPriorities,
			const wdi::D3D11X_MSAA_SAMPLE_POSITIONS* pSamplePositions) override;
		void SetResourceCompression(ID3D11Resource* pResource, UINT Compression) override;
		void SetResourceCompressionX(const wdi::D3D11X_DESCRIPTOR_RESOURCE* pResource, UINT Compression) override;
		void SetGDSRange(wdi::D3D11X_GDS_REGION_TYPE RegionType, UINT OffsetDwords, UINT NumDwords) override;
		void WriteGDS(wdi::D3D11X_GDS_REGION_TYPE RegionType, UINT OffsetDwords, UINT NumDwords,
			const UINT* pCounterValues, UINT Flags) override;
		void ReadGDS(wdi::D3D11X_GDS_REGION_TYPE RegionType, UINT OffsetDwords, UINT NumDwords, UINT* pCounterValues,
			UINT Flags) override;
		void VSSetShaderUserData(UINT StartSlot, UINT NumRegisters, const UINT* pData) override;
		void HSSetShaderUserData(UINT StartSlot, UINT NumRegisters, const UINT* pData) override;
		void DSSetShaderUserData(UINT StartSlot, UINT NumRegisters, const UINT* pData) override;
		void GSSetShaderUserData(UINT StartSlot, UINT NumRegisters, const UINT* pData) override;
		void PSSetShaderUserData(UINT StartSlot, UINT NumRegisters, const UINT* pData) override;
		void CSSetShaderUserData(UINT StartSlot, UINT NumRegisters, const UINT* pData) override;
		void InsertWaitOnMemory(const void* pAddress, UINT Flags, D3D11_COMPARISON_FUNC ComparisonFunction,
			UINT ReferenceValue, UINT Mask) override;
		void WriteTimestampToMemory(void* pDstAddress) override;
		void WriteTimestampToBuffer(ID3D11Buffer* pBuffer, UINT OffsetBytes) override;
		void StoreConstantRam(UINT Flags, ID3D11Buffer* pBuffer, UINT BufferOffsetInBytes, UINT CeRamOffsetInBytes,
			UINT SizeInBytes) override;
		void LoadConstantRam(UINT Flags, ID3D11Buffer* pBuffer, UINT BufferOffsetInBytes, UINT CeRamOffsetInBytes,
			UINT SizeInBytes) override;
		void WriteQuery(D3D11_QUERY QueryType, UINT QueryIndex, UINT Flags, ID3D11Buffer* pBuffer, UINT OffsetInBytes,
			UINT StrideInBytes) override;
		void ResetQuery(D3D11_QUERY QueryType, UINT QueryIndex, UINT Flags) override;
		void ConfigureQuery(D3D11_QUERY QueryType, const void* pConfiguration, UINT ConfigurationSize) override;
		void SetShaderUserData(wdi::D3D11X_HW_STAGE ShaderStage, UINT StartSlot, UINT NumRegisters,
			const UINT* pData) override;
		void SetPixelShaderDepthForceZOrder(BOOL ForceOrder) override;
		void SetPredicationFromQuery(D3D11_QUERY QueryType, ID3D11Buffer* pBuffer, UINT OffsetInBytes,
			UINT Flags) override;
		void SetBorderColorPalette(ID3D11Buffer* pBuffer, UINT OffsetInBytes, UINT Flags) override;
		void WriteValueEndOfPipe64(void* pDestination, UINT64 Value, UINT Flags) override;
		void InsertWaitOnMemory64(const void* pAddress, UINT Flags, D3D11_COMPARISON_FUNC ComparisonFunction,
			UINT64 ReferenceValue) override;
		void LoadConstantRamImmediate(UINT Flags, const void* pBuffer, UINT CeRamOffsetInBytes,
			UINT SizeInBytes) override;
		void SetScreenExtentsQuery(UINT Value) override;
		void CollectScreenExtents(UINT Flags, UINT AddressCount, const UINT64* pDestinationAddresses, USHORT ZMin,
			USHORT ZMax) override;
		void FillResourceWithValue(ID3D11Resource* pDstResource, UINT FillValue) override;
		void SetDrawBalancing(UINT BalancingMode, UINT Flags) override;
		void PSSetShaderResources(ID3D11ShaderResourceView* const* ppShaderResourceViews, UINT StartSlot,
			UINT PacketHeader) override;
		void PSSetShader(ID3D11PixelShader* pPixelShader) override;
		void PSSetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState* const* ppSamplers) override;
		void VSSetShader(ID3D11VertexShader* pVertexShader) override;
		void DrawIndexed(UINT64 StartIndexLocationAndIndexCount, INT BaseVertexLocation) override;
		void IASetIndexBuffer(UINT HardwareIndexFormat, ID3D11Buffer* pIndexBuffer, UINT Offset) override;
		void DrawIndexedInstanced(UINT64 StartIndexLocationAndIndexCountPerInstance,
			UINT64 BaseVertexLocationAndStartInstanceLocation, UINT InstanceCount) override;
		void DrawInstanced(UINT VertexCountPerInstance, UINT64 StartVertexLocationAndStartInstanceLocation,
			UINT InstanceCount) override;
		void GSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override;
		void GSSetShader(ID3D11GeometryShader* pShader) override;
		void VSSetShaderResources(ID3D11ShaderResourceView* const* ppShaderResourceViews, UINT StartSlot,
			UINT PacketHeader) override;
		void GSSetShaderResources(ID3D11ShaderResourceView* const* ppShaderResourceViews, UINT StartSlot,
			UINT PacketHeader) override;
		void DrawAuto() override;
		void HSSetShaderResources(ID3D11ShaderResourceView* const* ppShaderResourceViews, UINT StartSlot,
			UINT PacketHeader) override;
		void HSSetShader(ID3D11HullShader* pHullShader) override;
		void DSSetShaderResources(ID3D11ShaderResourceView* const* ppShaderResourceViews, UINT StartSlot,
			UINT PacketHeader) override;
		void DSSetShader(ID3D11DomainShader* pDomainShader) override;
		void CSSetShaderResources(ID3D11ShaderResourceView* const* ppShaderResourceViews, UINT StartSlot,
			UINT PacketHeader) override;
		void CSSetShader(ID3D11ComputeShader* pComputeShader) override;

	private:
		::ID3D11DeviceContext2* wrapped_interface;
	};
}


