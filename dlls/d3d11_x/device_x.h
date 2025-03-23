#pragma once
#include <cstdio>
#include <d3d11_1.h>
#include <d3d11_2.h>
#include "graphics_unknown.h"
#include <exception>
#include <format>
#include "dxgi_device.h"

namespace wdi
{
	class ID3D11DeviceContextX;
	struct D3D11X_COUNTER_SET_DESC;
	struct D3D11X_DESCRIPTOR_RESOURCE;
	struct D3D11_DMA_ENGINE_CONTEXT_DESC;
	struct D3D11X_SAMPLER_DESC;
	struct D3D11X_RENDERABLE_TEXTURE_ADDRESSES;
	struct D3D11X_DRIVER_STATISTICS;
	struct D3D11_COMPUTE_CONTEXT_DESC;
	struct D3D11X_RESOURCE_VIEW_DESC;
	struct D3D11X_DESCRIPTOR_SHADER_RESOURCE_VIEW;
	struct D3D11X_DESCRIPTOR_UNORDERED_ACCESS_VIEW;
	struct D3D11X_DESCRIPTOR_CONSTANT_BUFFER_VIEW;
	struct D3D11X_DESCRIPTOR_VERTEX_BUFFER_VIEW;
	struct D3D11X_SAMPLER_STATE_DESC;
	struct D3D11X_DESCRIPTOR_SAMPLER_STATE;
	class ID3D11CounterSetX;
	class ID3D11CounterSampleX;
	class ID3D11DmaEngineContextX;
	class ID3D11ComputeContextX;

	typedef UINT (*D3D11XHANGBEGINCALLBACK)(UINT64 Flags);
	typedef void (*D3D11XHANGPRINTCALLBACK)(const CHAR* strLine);
	typedef void (*D3D11XHANGDUMPCALLBACK)(const WCHAR* strFileName);

	typedef enum D3D11X_HARDWARE_VERSION
	{
		D3D11X_HARDWARE_VERSION_XBOX_ONE = 0,
		D3D11X_HARDWARE_VERSION_XBOX_ONE_S = 1,
		D3D11X_HARDWARE_VERSION_XBOX_ONE_X = 2,
		D3D11X_HARDWARE_VERSION_XBOX_ONE_X_DEVKIT = 3
	} D3D11X_HARDWARE_VERSION;

	struct D3D11X_GPU_HARDWARE_CONFIGURATION
	{
		UINT64 GpuFrequency;
		D3D11X_HARDWARE_VERSION HardwareVersion;
		UINT32 GpuCuCount;
	};

	D3DINTERFACE(ID3D11Device, db6f6ddb, ac77, 4e88, 82, 53, 81, 9d, f9, bb, f1, 40) : public wd::graphics_unknown
	{
	public:
		UINT m_CreationFlags;

		virtual HRESULT (CreateBuffer)(const D3D11_BUFFER_DESC* pDesc,
		                               const D3D11_SUBRESOURCE_DATA* pInitialData,
		                               ID3D11Buffer** ppBuffer) = 0;
		virtual HRESULT (CreateTexture1D)(const D3D11_TEXTURE1D_DESC* pDesc,
		                                  _In_reads_opt_(_Inexpressible_(pDesc->MipLevels* pDesc->ArraySize)) const
		                                  D3D11_SUBRESOURCE_DATA* pInitialData,
		                                  ID3D11Texture1D** ppTexture1D) = 0;
		virtual HRESULT (CreateTexture2D)(const D3D11_TEXTURE2D_DESC* pDesc,
		                                  _In_reads_opt_(_Inexpressible_(pDesc->MipLevels* pDesc->ArraySize)) const
		                                  D3D11_SUBRESOURCE_DATA* pInitialData,
		                                  ID3D11Texture2D** ppTexture2D) = 0;
		virtual HRESULT (CreateTexture3D)(const D3D11_TEXTURE3D_DESC* pDesc,
		                                  _In_reads_opt_(_Inexpressible_(pDesc->MipLevels)) const D3D11_SUBRESOURCE_DATA
		                                  * pInitialData, ID3D11Texture3D** ppTexture3D) = 0;
		virtual HRESULT (CreateShaderResourceView)(ID3D11Resource* pResource,
		                                           const D3D11_SHADER_RESOURCE_VIEW_DESC* pDesc,
		                                           ID3D11ShaderResourceView** ppSRView) = 0;
		virtual HRESULT (CreateUnorderedAccessView)(ID3D11Resource* pResource,
		                                            const D3D11_UNORDERED_ACCESS_VIEW_DESC* pDesc,
		                                            ID3D11UnorderedAccessView** ppUAView) = 0;
		virtual HRESULT (CreateRenderTargetView)(ID3D11Resource* pResource,
		                                         const D3D11_RENDER_TARGET_VIEW_DESC* pDesc,
		                                         ID3D11RenderTargetView** ppRTView) = 0;
		virtual HRESULT (CreateDepthStencilView)(ID3D11Resource* pResource,
		                                         const D3D11_DEPTH_STENCIL_VIEW_DESC* pDesc,
		                                         ID3D11DepthStencilView** ppDepthStencilView) = 0;
		virtual HRESULT (CreateInputLayout)(_In_reads_(NumElements) const D3D11_INPUT_ELEMENT_DESC* pInputElementDescs,
		                                    _In_range_(0, D3D11_IA_VERTEX_INPUT_STRUCTURE_ELEMENT_COUNT) UINT
		                                    NumElements,
		                                    _In_reads_(BytecodeLength) const void* pShaderBytecodeWithInputSignature,
		                                    SIZE_T BytecodeLength, ID3D11InputLayout** ppInputLayout) = 0;
		virtual HRESULT (CreateVertexShader)(_In_reads_(BytecodeLength) const void* pShaderBytecode,
		                                     SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage,
		                                     ID3D11VertexShader** ppVertexShader) = 0;
		virtual HRESULT (CreateGeometryShader)(
			_In_reads_(BytecodeLength) const void* pShaderBytecode, SIZE_T BytecodeLength,
			ID3D11ClassLinkage* pClassLinkage, ID3D11GeometryShader** ppGeometryShader) = 0;
		virtual HRESULT (CreateGeometryShaderWithStreamOutput)(
			_In_reads_(BytecodeLength) const void* pShaderBytecode, SIZE_T BytecodeLength,
			_In_reads_opt_(NumEntries) const D3D11_SO_DECLARATION_ENTRY* pSODeclaration,
			_In_range_(0, D3D11_SO_STREAM_COUNT* D3D11_SO_OUTPUT_COMPONENT_COUNT) UINT NumEntries,
			_In_reads_opt_(NumStrides) const UINT* pBufferStrides,
			_In_range_(0, D3D11_SO_BUFFER_SLOT_COUNT) UINT NumStrides, UINT RasterizedStream,
			ID3D11ClassLinkage* pClassLinkage, ID3D11GeometryShader** ppGeometryShader) = 0;
		virtual HRESULT (CreatePixelShader)(_In_reads_(BytecodeLength) const void* pShaderBytecode,
		                                    SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage,
		                                    ID3D11PixelShader** ppPixelShader) = 0;
		virtual HRESULT (CreateHullShader)(_In_reads_(BytecodeLength) const void* pShaderBytecode,
		                                   SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage,
		                                   ID3D11HullShader** ppHullShader) = 0;
		virtual HRESULT (CreateDomainShader)(_In_reads_(BytecodeLength) const void* pShaderBytecode,
		                                     SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage,
		                                     ID3D11DomainShader** ppDomainShader) = 0;
		virtual HRESULT (CreateComputeShader)(
			_In_reads_(BytecodeLength) const void* pShaderBytecode, SIZE_T BytecodeLength,
			ID3D11ClassLinkage* pClassLinkage, ID3D11ComputeShader** ppComputeShader) = 0;
		virtual HRESULT (CreateClassLinkage)(ID3D11ClassLinkage** ppLinkage) = 0;
		virtual HRESULT (CreateBlendState)(const D3D11_BLEND_DESC* pBlendStateDesc,
		                                   ID3D11BlendState** ppBlendState) = 0;
		virtual HRESULT (CreateDepthStencilState)(const D3D11_DEPTH_STENCIL_DESC* pDepthStencilDesc,
		                                          ID3D11DepthStencilState** ppDepthStencilState) = 0;
		virtual HRESULT (CreateRasterizerState)(const D3D11_RASTERIZER_DESC* pRasterizerDesc,
		                                        ID3D11RasterizerState** ppRasterizerState) = 0;
		virtual HRESULT (CreateSamplerState)(const D3D11_SAMPLER_DESC* pSamplerDesc,
		                                     ID3D11SamplerState** ppSamplerState) = 0;
		virtual HRESULT (CreateQuery)(const D3D11_QUERY_DESC* pQueryDesc, ID3D11Query** ppQuery) = 0;
		virtual HRESULT (CreatePredicate)(const D3D11_QUERY_DESC* pPredicateDesc,
		                                  ID3D11Predicate** ppPredicate) = 0;
		virtual HRESULT (CreateCounter)(const D3D11_COUNTER_DESC* pCounterDesc,
		                                ID3D11Counter** ppCounter) = 0;
		// @Patoke todo: make this access wdi::ID3D11DeviceContext instead, this is a temporary fix
		virtual HRESULT (CreateDeferredContext)(UINT ContextFlags, ::ID3D11DeviceContext** ppDeferredContext) = 0;
		virtual HRESULT (OpenSharedResource)(HANDLE hResource, REFIID ReturnedInterface,
		                                     void** ppResource) = 0;
		virtual HRESULT (CheckFormatSupport)(DXGI_FORMAT Format, UINT* pFormatSupport) = 0;
		virtual HRESULT (CheckMultisampleQualityLevels)(DXGI_FORMAT Format, UINT SampleCount,
		                                                UINT* pNumQualityLevels) = 0;
		virtual void (CheckCounterInfo)(D3D11_COUNTER_INFO* pCounterInfo) = 0;
		virtual HRESULT (CheckCounter)(const D3D11_COUNTER_DESC* pDesc, D3D11_COUNTER_TYPE* pType,
		                               UINT* pActiveCounters, _Out_writes_opt_(*pNameLength) LPSTR szName,
		                               _Inout_opt_ UINT* pNameLength, _Out_writes_opt_(*pUnitsLength) LPSTR szUnits,
		                               _Inout_opt_ UINT* pUnitsLength,
		                               _Out_writes_opt_(*pDescriptionLength) LPSTR szDescription,
		                               _Inout_opt_ UINT* pDescriptionLength) = 0;
		virtual HRESULT (CheckFeatureSupport)(D3D11_FEATURE Feature,
		                                      _Out_writes_bytes_(FeatureSupportDataSize) void* pFeatureSupportData,
		                                      UINT FeatureSupportDataSize) = 0;
		virtual HRESULT (GetPrivateData)(REFGUID guid, UINT* pDataSize,
		                                 _Out_writes_bytes_opt_(*pDataSize) void* pData) = 0;
		virtual HRESULT (SetPrivateData)(REFGUID guid, UINT DataSize,
		                                 _In_reads_bytes_opt_(DataSize) const void* pData) = 0;
		virtual HRESULT (SetPrivateDataInterface)(REFGUID guid, const IUnknown* pData) = 0;
		virtual HRESULT (SetPrivateDataInterfaceGraphics)(REFGUID guid, const IGraphicsUnknown* pData) = 0;
		virtual D3D_FEATURE_LEVEL (GetFeatureLevel)() = 0;
		virtual UINT (GetCreationFlags)() = 0;
		virtual HRESULT (GetDeviceRemovedReason)() = 0;
		// @Patoke todo: make this access wdi::ID3D11DeviceContext instead, this is a temporary fix
		virtual void (GetImmediateContext)(::ID3D11DeviceContext** ppImmediateContext) = 0;
		virtual HRESULT (SetExceptionMode)(UINT RaiseFlags) = 0;
		virtual UINT (GetExceptionMode)() = 0;
	};

	D3DINTERFACE(ID3D11Device1, a04bfb29, 08ef, 43d6, a4, 9c, a9, bd, bd, cb, e6, 86) : public ID3D11Device
	{
	public:
		// @Patoke todo: make this access wdi::ID3D11DeviceContext1 instead, this is a temporary fix
		virtual void (GetImmediateContext1)(::ID3D11DeviceContext1** ppImmediateContext) = 0;
		// @Patoke todo: make this access wdi::ID3D11DeviceContext1 instead, this is a temporary fix
		virtual HRESULT (CreateDeferredContext1)(UINT ContextFlags, ::ID3D11DeviceContext1** ppDeferredContext) = 0;
		virtual HRESULT (CreateBlendState1)(const D3D11_BLEND_DESC1* pBlendStateDesc,
		                                    ID3D11BlendState1** ppBlendState) = 0;
		virtual HRESULT (CreateRasterizerState1)(const D3D11_RASTERIZER_DESC1* pRasterizerDesc,
		                                         ID3D11RasterizerState1** ppRasterizerState) = 0;
		virtual HRESULT (CreateDeviceContextState)(
			UINT Flags,_In_reads_(FeatureLevels) const D3D_FEATURE_LEVEL* pFeatureLevels, UINT FeatureLevels,
			UINT SDKVersion,REFIID EmulatedInterface, D3D_FEATURE_LEVEL* pChosenFeatureLevel,
			ID3DDeviceContextState** ppContextState) = 0;
		virtual HRESULT (OpenSharedResource1)(HANDLE hResource,REFIID ReturnedInterface,
		                                      void** ppResource) = 0;
		virtual HRESULT (OpenSharedResourceByName)(LPCWSTR lpName, DWORD dwDesiredAccess,
		                                           REFIID ReturnedInterface, void** ppResource) = 0;
	};

	D3DINTERFACE(ID3D11Device2, 9d06dffa, d1e5, 4d07, 83, a8, 1b, b1, 23, f2, f8, 41) : public ID3D11Device1
	{
	public:
		// @Patoke todo: make this access wdi::ID3D11DeviceContext2 instead, this is a temporary fix
		virtual void (GetImmediateContext2)(::ID3D11DeviceContext2** ppImmediateContext) = 0;
		// @Patoke todo: make this access wdi::ID3D11DeviceContext2 instead, this is a temporary fix
		virtual HRESULT (CreateDeferredContext2)(UINT ContextFlags, ::ID3D11DeviceContext2** ppDeferredContext) = 0;
		virtual void (GetResourceTiling)(ID3D11Resource* pTiledResource, UINT* pNumTilesForEntireResource,
		                                 D3D11_PACKED_MIP_DESC* pPackedMipDesc,
		                                 D3D11_TILE_SHAPE* pStandardTileShapeForNonPackedMips,
		                                 _Inout_opt_ UINT* pNumSubresourceTilings, UINT FirstSubresourceTilingToGet,
		                                 _Out_writes_(*pNumSubresourceTilings) D3D11_SUBRESOURCE_TILING*
		                                 pSubresourceTilingsForNonPackedMips) = 0;
		virtual HRESULT (CheckMultisampleQualityLevels1)(DXGI_FORMAT Format, UINT SampleCount, UINT Flags,
		                                                 UINT* pNumQualityLevels) = 0;
	};

	D3DINTERFACE(ID3D11DeviceX, 177700f9, 876a, 4436, b3, 68, 36, a6, 04, f8, 2c, ef) : public ID3D11Device2
	{
	public:
		virtual void (GetImmediateContextX)(ID3D11DeviceContextX** ppImmediateContextX) = 0;
		virtual HRESULT (CreateCounterSet)(const D3D11X_COUNTER_SET_DESC* pCounterSetDesc,
		                                   ID3D11CounterSetX** ppCounterSet) = 0;
		virtual HRESULT (CreateCounterSample)(ID3D11CounterSampleX** ppCounterSample) = 0;
		virtual HRESULT (SetDriverHint)(UINT Feature, UINT Value) = 0;
		virtual HRESULT (CreateDmaEngineContext)(const D3D11_DMA_ENGINE_CONTEXT_DESC* pDmaEngineContextDesc,
		                                         ID3D11DmaEngineContextX** ppDmaDeviceContext) = 0;
		virtual BOOL (IsFencePending)(UINT64 Fence) = 0;
		virtual BOOL (IsResourcePending)(ID3D11Resource* pResource) = 0;
		virtual HRESULT (CreatePlacementBuffer)(const D3D11_BUFFER_DESC* pDesc, void* pVirtualAddress,
		                                        ID3D11Buffer** ppBuffer) = 0;
		virtual HRESULT (CreatePlacementTexture1D)(const D3D11_TEXTURE1D_DESC* pDesc, UINT TileModeIndex, UINT Pitch,
		                                           void* pVirtualAddress, ID3D11Texture1D** ppTexture1D) = 0;
		virtual HRESULT (CreatePlacementTexture2D)(const D3D11_TEXTURE2D_DESC* pDesc, UINT TileModeIndex, UINT Pitch,
		                                           void* pVirtualAddress, ID3D11Texture2D** ppTexture2D) = 0;
		virtual HRESULT (CreatePlacementTexture3D)(const D3D11_TEXTURE3D_DESC* pDesc, UINT TileModeIndex, UINT Pitch,
		                                           void* pVirtualAddress, ID3D11Texture3D** ppTexture3D) = 0;
		virtual void (GetTimestamps)(UINT64* pGpuTimestamp, UINT64* pCpuRdtscTimestamp) = 0;
		virtual HRESULT (CreateSamplerStateX)(const D3D11X_SAMPLER_DESC* pSamplerDesc,
		                                      ID3D11SamplerState** ppSamplerState) = 0;
		virtual HRESULT (CreateDeferredContextX)(UINT Flags, ID3D11DeviceContextX** ppDeferredContext) = 0;
		virtual void (GarbageCollect)(UINT Flags) = 0;
		virtual HRESULT (CreateDepthStencilStateX)(const D3D11_DEPTH_STENCIL_DESC* pDepthStencilStateDesc,
		                                           ID3D11DepthStencilState** ppDepthStencilState) = 0;
		virtual HRESULT (CreatePlacementRenderableTexture2D)(const D3D11_TEXTURE2D_DESC* pDesc, UINT TileModeIndex,
		                                                     UINT Pitch,
		                                                     const D3D11X_RENDERABLE_TEXTURE_ADDRESSES* pAddresses,
		                                                     ID3D11Texture2D** ppTexture2D) = 0;
		virtual void (GetDriverStatistics)(UINT StructSize, D3D11X_DRIVER_STATISTICS* pStatistics) = 0;
		virtual HRESULT (CreateComputeContextX)(const D3D11_COMPUTE_CONTEXT_DESC* pComputeContextDesc,
		                                        ID3D11ComputeContextX** ppComputeContext) = 0;
		virtual void (ComposeShaderResourceView)(const D3D11X_DESCRIPTOR_RESOURCE* pDescriptorResource,
		                                         const D3D11X_RESOURCE_VIEW_DESC* pViewDesc,
		                                         D3D11X_DESCRIPTOR_SHADER_RESOURCE_VIEW* pDescriptorSrv) = 0;
		virtual void (ComposeUnorderedAccessView)(const D3D11X_DESCRIPTOR_RESOURCE* pDescriptorResource,
		                                          const D3D11X_RESOURCE_VIEW_DESC* pViewDesc,
		                                          D3D11X_DESCRIPTOR_UNORDERED_ACCESS_VIEW* pDescriptorUav) = 0;
		virtual void (ComposeConstantBufferView)(const D3D11X_DESCRIPTOR_RESOURCE* pDescriptorResource,
		                                         const D3D11X_RESOURCE_VIEW_DESC* pViewDesc,
		                                         D3D11X_DESCRIPTOR_CONSTANT_BUFFER_VIEW* pDescriptorCb) = 0;
		virtual void (ComposeVertexBufferView)(const D3D11X_DESCRIPTOR_RESOURCE* pDescriptorResource,
		                                       const D3D11X_RESOURCE_VIEW_DESC* pViewDesc,
		                                       D3D11X_DESCRIPTOR_VERTEX_BUFFER_VIEW* pDescriptorVb) = 0;
		virtual void (ComposeSamplerState)(const D3D11X_SAMPLER_STATE_DESC* pSamplerDesc,
		                                   D3D11X_DESCRIPTOR_SAMPLER_STATE* pDescriptorSamplerState) = 0;
		virtual void (PlaceSwapChainView)(ID3D11Resource* pSwapChainBuffer, ID3D11View* pView) = 0;
		virtual void (SetDebugFlags)(UINT Flags) = 0;
		virtual UINT (GetDebugFlags)() = 0;
		virtual void (SetHangCallbacks)(D3D11XHANGBEGINCALLBACK pBeginCallback, D3D11XHANGPRINTCALLBACK pPrintCallback,
		                                D3D11XHANGDUMPCALLBACK pDumpCallback) = 0;
		virtual void (ReportGpuHang)(UINT Flags) = 0;
		virtual HRESULT (SetGpuMemoryPriority)(UINT Priority) = 0;
		virtual void (GetGpuHardwareConfiguration)(D3D11X_GPU_HARDWARE_CONFIGURATION* pGpuHardwareConfiguration) = 0;
	};

	D3DINTERFACE(ID3D11PerformanceDeviceX, 88671610, 712E, 4F1E, 84, AB, 01, B5, 94, 8B, D3, 73) : public ID3D11DeviceX{};
}

namespace wd
{
	class device_x : public wdi::ID3D11DeviceX
	{
	public:
		device_x(::ID3D11Device2* device) : wrapped_interface(device) { wrapped_interface->AddRef(); }

		IGU_DEFINE_REF

		HRESULT QueryInterface(REFIID riid, void** ppvObject) override
		{
			if (ppvObject == nullptr) {
				return E_POINTER;
			}

			if (riid == __uuidof(wdi::ID3D11DeviceX) || riid == __uuidof(wdi::ID3D11Device) || riid == __uuidof(wdi::ID3D11Device1) || riid == __uuidof(wdi::ID3D11Device2)
			|| riid == __uuidof(wdi::ID3D11PerformanceDeviceX))
			{
				*ppvObject = static_cast<wdi::ID3D11DeviceX*>(this);
				AddRef( );
				return S_OK;
			}

			if (riid == __uuidof(IDXGIDevice) ||
				riid == __uuidof(IDXGIDevice1))
			{
				wrapped_interface->QueryInterface(__uuidof(IDXGIDevice1), ppvObject);
				*ppvObject = new dxgi_device(static_cast<IDXGIDevice1*>(*ppvObject));
				return S_OK;
			}

			if (riid == __uuidof(wdi::IGraphicsUnwrap))
			{
				*ppvObject = wrapped_interface;
				return S_OK;
			}

			TRACE_INTERFACE_NOT_HANDLED("device_x");
			*ppvObject = nullptr;
			return E_NOINTERFACE;
		}

		HRESULT CreateBuffer(const D3D11_BUFFER_DESC* pDesc, const D3D11_SUBRESOURCE_DATA* pInitialData, ID3D11Buffer** ppBuffer) override;

		HRESULT CreateTexture1D(const D3D11_TEXTURE1D_DESC* pDesc, const D3D11_SUBRESOURCE_DATA* pInitialData, ID3D11Texture1D** ppTexture1D) override;

		HRESULT CreateTexture2D(const D3D11_TEXTURE2D_DESC* pDesc, const D3D11_SUBRESOURCE_DATA* pInitialData, ID3D11Texture2D** ppTexture2D) override;

		HRESULT CreateTexture3D(const D3D11_TEXTURE3D_DESC* pDesc, const D3D11_SUBRESOURCE_DATA* pInitialData, ID3D11Texture3D** ppTexture3D) override;

		HRESULT CreateShaderResourceView(ID3D11Resource* pResource, const D3D11_SHADER_RESOURCE_VIEW_DESC* pDesc, ID3D11ShaderResourceView** ppSRView) override;

		HRESULT CreateUnorderedAccessView(ID3D11Resource* pResource, const D3D11_UNORDERED_ACCESS_VIEW_DESC* pDesc, ID3D11UnorderedAccessView** ppUAView) override;

		HRESULT CreateRenderTargetView(ID3D11Resource* pResource, const D3D11_RENDER_TARGET_VIEW_DESC* pDesc, ID3D11RenderTargetView** ppRTView) override;

		HRESULT CreateDepthStencilView(ID3D11Resource* pResource, const D3D11_DEPTH_STENCIL_VIEW_DESC* pDesc, ID3D11DepthStencilView** ppDepthStencilView) override;

		HRESULT CreateInputLayout(const D3D11_INPUT_ELEMENT_DESC* pInputElementDescs, UINT NumElements, const void* pShaderBytecodeWithInputSignature, SIZE_T BytecodeLength, ID3D11InputLayout** ppInputLayout) override
		{
			return wrapped_interface->CreateInputLayout(pInputElementDescs, NumElements, pShaderBytecodeWithInputSignature, BytecodeLength, ppInputLayout);
		}

		HRESULT CreateVertexShader(const void* pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage, ID3D11VertexShader** ppVertexShader) override
		{
			return wrapped_interface->CreateVertexShader(pShaderBytecode, BytecodeLength, pClassLinkage, ppVertexShader);
		}

		HRESULT CreateGeometryShader(const void* pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage, ID3D11GeometryShader** ppGeometryShader) override
		{
			return wrapped_interface->CreateGeometryShader(pShaderBytecode, BytecodeLength, pClassLinkage, ppGeometryShader);
		}

		HRESULT CreateGeometryShaderWithStreamOutput(const void* pShaderBytecode, SIZE_T BytecodeLength, const D3D11_SO_DECLARATION_ENTRY* pSODeclaration, UINT NumEntries, const UINT* pBufferStrides, UINT NumStrides, UINT RasterizedStream, ID3D11ClassLinkage* pClassLinkage, ID3D11GeometryShader** ppGeometryShader) override
		{
			return wrapped_interface->CreateGeometryShaderWithStreamOutput(pShaderBytecode, BytecodeLength, pSODeclaration, NumEntries, pBufferStrides, NumStrides, RasterizedStream, pClassLinkage, ppGeometryShader);
		}

		HRESULT CreatePixelShader(const void* pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage, ID3D11PixelShader** ppPixelShader) override
		{
			return wrapped_interface->CreatePixelShader(pShaderBytecode, BytecodeLength, pClassLinkage, ppPixelShader);
		}

		HRESULT CreateHullShader(const void* pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage, ID3D11HullShader** ppHullShader) override
		{
			return wrapped_interface->CreateHullShader(pShaderBytecode, BytecodeLength, pClassLinkage, ppHullShader);
		}

		HRESULT CreateDomainShader(const void* pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage, ID3D11DomainShader** ppDomainShader) override
		{
			return wrapped_interface->CreateDomainShader(pShaderBytecode, BytecodeLength, pClassLinkage, ppDomainShader);
		}

		HRESULT CreateComputeShader(const void* pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage, ID3D11ComputeShader** ppComputeShader) override
		{
			return wrapped_interface->CreateComputeShader(pShaderBytecode, BytecodeLength, pClassLinkage, ppComputeShader);
		}

		HRESULT CreateClassLinkage(ID3D11ClassLinkage** ppLinkage) override
		{
			return wrapped_interface->CreateClassLinkage(ppLinkage);
		}

		HRESULT CreateBlendState(const D3D11_BLEND_DESC* pBlendStateDesc, ID3D11BlendState** ppBlendState) override
		{
			return wrapped_interface->CreateBlendState(pBlendStateDesc, ppBlendState);
		}

		HRESULT CreateDepthStencilState(const D3D11_DEPTH_STENCIL_DESC* pDepthStencilDesc, ID3D11DepthStencilState** ppDepthStencilState) override
		{
			return wrapped_interface->CreateDepthStencilState(pDepthStencilDesc, ppDepthStencilState);
		}

		HRESULT CreateRasterizerState(const D3D11_RASTERIZER_DESC* pRasterizerDesc, ID3D11RasterizerState** ppRasterizerState) override
		{
			return wrapped_interface->CreateRasterizerState(pRasterizerDesc, ppRasterizerState);
		}

		HRESULT CreateSamplerState(const D3D11_SAMPLER_DESC* pSamplerDesc, ID3D11SamplerState** ppSamplerState) override
		{
			return wrapped_interface->CreateSamplerState(pSamplerDesc, ppSamplerState);
		}

		HRESULT CreateQuery(const D3D11_QUERY_DESC* pQueryDesc, ID3D11Query** ppQuery) override
		{
			return wrapped_interface->CreateQuery(pQueryDesc, ppQuery);
		}

		HRESULT CreatePredicate(const D3D11_QUERY_DESC* pPredicateDesc, ID3D11Predicate** ppPredicate) override
		{
			return wrapped_interface->CreatePredicate(pPredicateDesc, ppPredicate);
		}

		HRESULT CreateCounter(const D3D11_COUNTER_DESC* pCounterDesc, ID3D11Counter** ppCounter) override
		{
			return wrapped_interface->CreateCounter(pCounterDesc, ppCounter);
		}

		HRESULT CreateDeferredContext(UINT ContextFlags, ID3D11DeviceContext** ppDeferredContext) override;

		HRESULT OpenSharedResource(HANDLE hResource, REFIID ReturnedInterface, void** ppResource) override
		{
			return wrapped_interface->OpenSharedResource(hResource, ReturnedInterface, ppResource);
		}

		HRESULT CheckFormatSupport(DXGI_FORMAT Format, UINT* pFormatSupport) override
		{
			return wrapped_interface->CheckFormatSupport(Format, pFormatSupport);
		}

		HRESULT CheckMultisampleQualityLevels(DXGI_FORMAT Format, UINT SampleCount, UINT* pNumQualityLevels) override
		{
			return wrapped_interface->CheckMultisampleQualityLevels(Format, SampleCount, pNumQualityLevels);
		}

		void CheckCounterInfo(D3D11_COUNTER_INFO* pCounterInfo) override
		{
			wrapped_interface->CheckCounterInfo(pCounterInfo);
		}

		HRESULT CheckCounter(const D3D11_COUNTER_DESC* pDesc, D3D11_COUNTER_TYPE* pType, UINT* pActiveCounters, LPSTR szName, UINT* pNameLength, LPSTR szUnits, UINT* pUnitsLength, LPSTR szDescription, UINT* pDescriptionLength) override
		{
			return wrapped_interface->CheckCounter(pDesc, pType, pActiveCounters, szName, pNameLength, szUnits, pUnitsLength, szDescription, pDescriptionLength);
		}

		HRESULT CheckFeatureSupport(D3D11_FEATURE Feature, void* pFeatureSupportData, UINT FeatureSupportDataSize) override
		{
			return wrapped_interface->CheckFeatureSupport(Feature, pFeatureSupportData, FeatureSupportDataSize);
		}

		HRESULT GetPrivateData(REFGUID guid, UINT* pDataSize, void* pData) override
		{
			return wrapped_interface->GetPrivateData(guid, pDataSize, pData);
		}

		HRESULT SetPrivateData(REFGUID guid, UINT DataSize, const void* pData) override
		{
			return wrapped_interface->SetPrivateData(guid, DataSize, pData);
		}

		HRESULT SetPrivateDataInterface(REFGUID guid, const IUnknown* pData) override
		{
			return wrapped_interface->SetPrivateDataInterface(guid, pData);
		}

		HRESULT SetPrivateDataInterfaceGraphics(REFGUID guid, const IGraphicsUnknown* pData) override
		{
			throw std::exception("Not implemented");
			//return wrapped_interface->SetPrivateDataInterfaceGraphics(guid, pData);
		}

		D3D_FEATURE_LEVEL GetFeatureLevel( ) override
		{
			return wrapped_interface->GetFeatureLevel( );
		}

		UINT GetCreationFlags( ) override
		{
			return wrapped_interface->GetCreationFlags( );
		}

		HRESULT GetDeviceRemovedReason( ) override
		{
			return wrapped_interface->GetDeviceRemovedReason( );
		}

		void GetImmediateContext(ID3D11DeviceContext** ppImmediateContext) override;

		HRESULT SetExceptionMode(UINT RaiseFlags) override
		{
			return wrapped_interface->SetExceptionMode(RaiseFlags);
		}

		UINT GetExceptionMode( ) override
		{
			return wrapped_interface->GetExceptionMode( );
		}

		// ID3D11Device1 methods
		void GetImmediateContext1(ID3D11DeviceContext1** ppImmediateContext) override
		{
			wrapped_interface->GetImmediateContext1(ppImmediateContext);
		}

		HRESULT CreateDeferredContext1(UINT ContextFlags, ID3D11DeviceContext1** ppDeferredContext) override;

		HRESULT CreateBlendState1(const D3D11_BLEND_DESC1* pBlendStateDesc, ID3D11BlendState1** ppBlendState) override
		{
			return wrapped_interface->CreateBlendState1(pBlendStateDesc, ppBlendState);
		}

		HRESULT CreateRasterizerState1(const D3D11_RASTERIZER_DESC1* pRasterizerDesc, ID3D11RasterizerState1** ppRasterizerState) override
		{
			return wrapped_interface->CreateRasterizerState1(pRasterizerDesc, ppRasterizerState);
		}

		HRESULT CreateDeviceContextState(UINT Flags, const D3D_FEATURE_LEVEL* pFeatureLevels, UINT FeatureLevels, UINT SDKVersion, REFIID EmulatedInterface, D3D_FEATURE_LEVEL* pChosenFeatureLevel, ID3DDeviceContextState** ppContextState) override
		{
			return wrapped_interface->CreateDeviceContextState(Flags, pFeatureLevels, FeatureLevels, SDKVersion, EmulatedInterface, pChosenFeatureLevel, ppContextState);
		}

		HRESULT OpenSharedResource1(HANDLE hResource, REFIID ReturnedInterface, void** ppResource) override
		{
			return wrapped_interface->OpenSharedResource1(hResource, ReturnedInterface, ppResource);
		}

		HRESULT OpenSharedResourceByName(LPCWSTR lpName, DWORD dwDesiredAccess, REFIID ReturnedInterface, void** ppResource) override
		{
			return wrapped_interface->OpenSharedResourceByName(lpName, dwDesiredAccess, ReturnedInterface, ppResource);
		}

		// ID3D11Device2 methods
		void GetImmediateContext2(ID3D11DeviceContext2** ppImmediateContext) override
		{
			wrapped_interface->GetImmediateContext2(ppImmediateContext);
		}

		HRESULT CreateDeferredContext2(UINT ContextFlags, ID3D11DeviceContext2** ppDeferredContext) override;

		void GetResourceTiling(ID3D11Resource* pTiledResource, UINT* pNumTilesForEntireResource, D3D11_PACKED_MIP_DESC* pPackedMipDesc, D3D11_TILE_SHAPE* pStandardTileShapeForNonPackedMips, UINT* pNumSubresourceTilings, UINT FirstSubresourceTilingToGet, D3D11_SUBRESOURCE_TILING* pSubresourceTilingsForNonPackedMips) override
		{
			wrapped_interface->GetResourceTiling(pTiledResource, pNumTilesForEntireResource, pPackedMipDesc, pStandardTileShapeForNonPackedMips, pNumSubresourceTilings, FirstSubresourceTilingToGet, pSubresourceTilingsForNonPackedMips);
		}

		HRESULT CheckMultisampleQualityLevels1(DXGI_FORMAT Format, UINT SampleCount, UINT Flags, UINT* pNumQualityLevels) override
		{
			return wrapped_interface->CheckMultisampleQualityLevels1(Format, SampleCount, Flags, pNumQualityLevels);
		}

		// ID3D11DeviceX methods
		void GetImmediateContextX(wdi::ID3D11DeviceContextX** ppImmediateContextX) override;
		HRESULT CreateCounterSet(const wdi::D3D11X_COUNTER_SET_DESC* pCounterSetDesc,
										   wdi::ID3D11CounterSetX** ppCounterSet) override;
		HRESULT CreateCounterSample(wdi::ID3D11CounterSampleX** ppCounterSample) override;
		HRESULT SetDriverHint(UINT Feature, UINT Value) override;
		HRESULT CreateDmaEngineContext(const wdi::D3D11_DMA_ENGINE_CONTEXT_DESC* pDmaEngineContextDesc,
												 wdi::ID3D11DmaEngineContextX** ppDmaDeviceContext) override;
		BOOL IsFencePending(UINT64 Fence) override;
		BOOL IsResourcePending(ID3D11Resource* pResource) override;
		HRESULT CreatePlacementBuffer(const D3D11_BUFFER_DESC* pDesc, void* pVirtualAddress,
		                                        ID3D11Buffer** ppBuffer) override;
		HRESULT CreatePlacementTexture1D(const D3D11_TEXTURE1D_DESC* pDesc, UINT TileModeIndex, UINT Pitch,
		                                           void* pVirtualAddress, ID3D11Texture1D** ppTexture1D) override;
		HRESULT CreatePlacementTexture2D(const D3D11_TEXTURE2D_DESC* pDesc, UINT TileModeIndex, UINT Pitch,
		                                           void* pVirtualAddress, ID3D11Texture2D** ppTexture2D) override;
		HRESULT CreatePlacementTexture3D(const D3D11_TEXTURE3D_DESC* pDesc, UINT TileModeIndex, UINT Pitch,
		                                           void* pVirtualAddress, ID3D11Texture3D** ppTexture3D) override;
		void GetTimestamps(UINT64* pGpuTimestamp, UINT64* pCpuRdtscTimestamp) override;
		HRESULT CreateSamplerStateX(const wdi::D3D11X_SAMPLER_DESC* pSamplerDesc,
		                                      ID3D11SamplerState** ppSamplerState) override;
		HRESULT CreateDeferredContextX(UINT Flags, wdi::ID3D11DeviceContextX** ppDeferredContext) override;
		void GarbageCollect(UINT Flags) override;
		HRESULT CreateDepthStencilStateX(const D3D11_DEPTH_STENCIL_DESC* pDepthStencilStateDesc,
		                                           ID3D11DepthStencilState** ppDepthStencilState) override;
		HRESULT CreatePlacementRenderableTexture2D(const D3D11_TEXTURE2D_DESC* pDesc, UINT TileModeIndex,
		                                                     UINT Pitch,
		                                                     const wdi::D3D11X_RENDERABLE_TEXTURE_ADDRESSES* pAddresses,
		                                                     ID3D11Texture2D** ppTexture2D) override;
		void GetDriverStatistics(UINT StructSize, wdi::D3D11X_DRIVER_STATISTICS* pStatistics) override;
		HRESULT CreateComputeContextX(const wdi::D3D11_COMPUTE_CONTEXT_DESC* pComputeContextDesc,
												wdi::ID3D11ComputeContextX** ppComputeContext) override;
		void ComposeShaderResourceView(const wdi::D3D11X_DESCRIPTOR_RESOURCE* pDescriptorResource,
												 const wdi::D3D11X_RESOURCE_VIEW_DESC* pViewDesc,
												 wdi::D3D11X_DESCRIPTOR_SHADER_RESOURCE_VIEW* pDescriptorSrv) override;
		void ComposeUnorderedAccessView(const wdi::D3D11X_DESCRIPTOR_RESOURCE* pDescriptorResource,
												  const wdi::D3D11X_RESOURCE_VIEW_DESC* pViewDesc,
												  wdi::D3D11X_DESCRIPTOR_UNORDERED_ACCESS_VIEW* pDescriptorUav) override;
		void ComposeConstantBufferView(const wdi::D3D11X_DESCRIPTOR_RESOURCE* pDescriptorResource,
												 const wdi::D3D11X_RESOURCE_VIEW_DESC* pViewDesc,
												 wdi::D3D11X_DESCRIPTOR_CONSTANT_BUFFER_VIEW* pDescriptorCb) override;
		void ComposeVertexBufferView(const wdi::D3D11X_DESCRIPTOR_RESOURCE* pDescriptorResource,
											   const wdi::D3D11X_RESOURCE_VIEW_DESC* pViewDesc,
											   wdi::D3D11X_DESCRIPTOR_VERTEX_BUFFER_VIEW* pDescriptorVb) override;
		void ComposeSamplerState(const wdi::D3D11X_SAMPLER_STATE_DESC* pSamplerDesc,
										   wdi::D3D11X_DESCRIPTOR_SAMPLER_STATE* pDescriptorSamplerState) override;
		void PlaceSwapChainView(ID3D11Resource* pSwapChainBuffer, ID3D11View* pView) override;
		void SetDebugFlags(UINT Flags) override;
		UINT GetDebugFlags() override;
		void SetHangCallbacks(wdi::D3D11XHANGBEGINCALLBACK pBeginCallback, wdi::D3D11XHANGPRINTCALLBACK pPrintCallback,
		                                wdi::D3D11XHANGDUMPCALLBACK pDumpCallback) override;
		void ReportGpuHang(UINT Flags) override;
		HRESULT SetGpuMemoryPriority(UINT Priority) override;
		void GetGpuHardwareConfiguration(wdi::D3D11X_GPU_HARDWARE_CONFIGURATION* pGpuHardwareConfiguration) override;
	private:
		::ID3D11Device2* wrapped_interface;
	};
}
