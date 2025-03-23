#pragma once
#include <emmintrin.h>
#include "device_child_x.h"
#include "resource.hpp"

namespace wdi
{
	#define D3D11X_DESCRIPTOR_TEXTURE_VIEW_SIZE_IN_OWORDS 2
    #define D3D11X_DESCRIPTOR_TEXTURE_VIEW_SIZE_IN_QWORDS 4
    #define D3D11X_DESCRIPTOR_TEXTURE_VIEW_SIZE_IN_DWORDS 8
    #define D3D11X_DESCRIPTOR_TEXTURE_VIEW_SIZE_IN_BYTES 32

    typedef struct D3D11X_DESCRIPTOR_TEXTURE_VIEW
    {
        union
        {
            __m128i Oword[ D3D11X_DESCRIPTOR_TEXTURE_VIEW_SIZE_IN_OWORDS ];
            UINT64 Qword[ D3D11X_DESCRIPTOR_TEXTURE_VIEW_SIZE_IN_QWORDS ];
            UINT32 Dword[ D3D11X_DESCRIPTOR_TEXTURE_VIEW_SIZE_IN_DWORDS ];
        };

    } D3D11X_DESCRIPTOR_TEXTURE_VIEW;

	D3DINTERFACE(ID3D11View, 839d1216, bb2e, 412b, b7, f4, a9, db, eb, e0, 8e, d1) : public ID3D11DeviceChild
	{
	public:
		ID3D11Resource* m_pResource;
		unsigned int m_Type;

		virtual void STDMETHODCALLTYPE GetResource(
			/* [annotation] */
			_Outptr_  ID3D11Resource** ppResource) PURE;
	};

    D3DINTERFACE(ID3D11RenderTargetView, dfdba067, 0b8d, 4865, 87, 5b, d7, b4, 51, 6c, c1, 64) : public ID3D11View
    {
    public:
        virtual void STDMETHODCALLTYPE GetDesc(
            /* [annotation] */
            _Out_  D3D11_RENDER_TARGET_VIEW_DESC* pDesc) PURE;

    };

    D3DINTERFACE(ID3D11DepthStencilView, 9fdac92a, 1876, 48c3, af, ad, 25, b9, 4f, 84, a9, b6) : public ID3D11View
    {
    public:
        virtual void STDMETHODCALLTYPE GetDesc(
            /* [annotation] */
            _Out_  D3D11_DEPTH_STENCIL_VIEW_DESC* pDesc) PURE;

    };

    D3DINTERFACE(ID3D11ShaderResourceView, b0e06fe0, 8192, 4e1a, b1, ca, 36, d7, 41, 47, 10, b2) : public ID3D11View
    {
    public:
        virtual void STDMETHODCALLTYPE GetDesc(
            /* [annotation] */
            _Out_  D3D11_SHADER_RESOURCE_VIEW_DESC* pDesc) PURE;

    };

    D3DINTERFACE(ID3D11UnorderedAccessView, 28acf509, 7f5c, 48f6, 86, 11, f3, 16, 01, 0a, 63, 80) : public ID3D11View
    {
    public:
        D3D11X_DESCRIPTOR_TEXTURE_VIEW m_Descriptor;
        void* m_pAllocationStart;

        virtual void STDMETHODCALLTYPE GetDesc(
            /* [annotation] */
            _Out_  D3D11_UNORDERED_ACCESS_VIEW_DESC* pDesc) PURE;

    };
}

namespace wd
{
    class render_target_view : public wdi::ID3D11RenderTargetView
    {
    public:
        render_target_view(::ID3D11RenderTargetView* view) : wrapped_interface(view)
        {
            m_pResource = reinterpret_cast<wdi::ID3D11Resource*>(wrapped_interface);
        	wrapped_interface->AddRef( );
        }
        IGU_DEFINE_REF

    	HRESULT QueryInterface(const IID& riid, void** ppvObject) override
        {
            if (riid == __uuidof(wdi::ID3D11RenderTargetView) || riid == __uuidof(wdi::ID3D11View) || riid == __uuidof(wdi::ID3D11DepthStencilView))
            {
                *ppvObject = this;
                AddRef( );
                return S_OK;
            }
            TRACE_INTERFACE_NOT_HANDLED("render_target_view");
            *ppvObject = nullptr;
            return E_NOINTERFACE;
        }

        void STDMETHODCALLTYPE GetDesc(D3D11_RENDER_TARGET_VIEW_DESC* pDesc) override
        {
            wrapped_interface->GetDesc(pDesc);
        }

        void GetDevice(ID3D11Device** ppDevice) override
        {
			printf("WARN: render_target_view::GetDevice returns a PC device!!\n");
			wrapped_interface->GetDevice(ppDevice);
        }

        HRESULT GetPrivateData(const GUID& guid, UINT* pDataSize, void* pData) override
        {
			return wrapped_interface->GetPrivateData(guid, pDataSize, pData);
        }

        HRESULT SetPrivateData(const GUID& guid, UINT DataSize, const void* pData) override
        {
			return wrapped_interface->SetPrivateData(guid, DataSize, pData);
        }

        HRESULT SetPrivateDataInterface(const GUID& guid, const IUnknown* pData) override
        {
			return wrapped_interface->SetPrivateDataInterface(guid, pData);
        }

        HRESULT SetPrivateDataInterfaceGraphics(const GUID& guid, const IGraphicsUnknown* pData) override
        {
            TRACE_NOT_IMPLEMENTED("render_target_view");
			return E_NOTIMPL;
        }

        HRESULT SetName(LPCWSTR pName) override
        {
            TRACE_NOT_IMPLEMENTED("render_target_view");
            return E_NOTIMPL;
        }

        void GetResource(wdi::ID3D11Resource** ppResource) override
        {
            D3D11_RENDER_TARGET_VIEW_DESC desc;
            wrapped_interface->GetDesc(&desc);

			// FIXME: this only targets 2D textures, but it doesn't matter since all texture* classes are the same
            ::ID3D11Texture2D* texture2d = nullptr;
            wrapped_interface->GetResource(reinterpret_cast<::ID3D11Resource**>(&texture2d));
            *reinterpret_cast<wdi::ID3D11Texture2D**>(ppResource) = new texture_2d(texture2d);
        }

        ::ID3D11RenderTargetView* wrapped_interface;
    };

	class depth_stencil_view : public wdi::ID3D11DepthStencilView
    {
    public:
        depth_stencil_view(::ID3D11DepthStencilView* view) : wrapped_interface(view)
        {
            m_pResource = reinterpret_cast<wdi::ID3D11Resource*>(wrapped_interface);
            wrapped_interface->AddRef( );
        }
        IGU_DEFINE_REF

		HRESULT QueryInterface(const IID& riid, void** ppvObject) override
        {
            if (riid == __uuidof(wdi::ID3D11DepthStencilView) || riid == __uuidof(wdi::ID3D11View))
            {
                *ppvObject = this;
                AddRef( );
                return S_OK;
            }
            TRACE_INTERFACE_NOT_HANDLED("depth_stencil_view");
            *ppvObject = nullptr;
            return E_NOINTERFACE;
        }

        void STDMETHODCALLTYPE GetDesc(D3D11_DEPTH_STENCIL_VIEW_DESC* pDesc) override
        {
            wrapped_interface->GetDesc(pDesc);
        }

        void GetDevice(ID3D11Device** ppDevice) override
        {
            printf("WARN: depth_stencil_view::GetDevice returns a PC device!!\n");
            wrapped_interface->GetDevice(ppDevice);
        }

        HRESULT GetPrivateData(const GUID& guid, UINT* pDataSize, void* pData) override
        {
            return wrapped_interface->GetPrivateData(guid, pDataSize, pData);
        }

        HRESULT SetPrivateData(const GUID& guid, UINT DataSize, const void* pData) override
        {
            return wrapped_interface->SetPrivateData(guid, DataSize, pData);
        }

        HRESULT SetPrivateDataInterface(const GUID& guid, const IUnknown* pData) override
        {
            return wrapped_interface->SetPrivateDataInterface(guid, pData);
        }

        HRESULT SetPrivateDataInterfaceGraphics(const GUID& guid, const IGraphicsUnknown* pData) override
        {
            TRACE_NOT_IMPLEMENTED("depth_stencil_view");
            return E_NOTIMPL;
        }

        HRESULT SetName(LPCWSTR pName) override
        {
            TRACE_NOT_IMPLEMENTED("depth_stencil_view");
            return E_NOTIMPL;
        }

        void GetResource(wdi::ID3D11Resource** ppResource) override
        {
            D3D11_DEPTH_STENCIL_VIEW_DESC desc;
            wrapped_interface->GetDesc(&desc);

            // FIXME: this only targets 2D textures, but it doesn't matter since all texture* classes are the same
            ::ID3D11Texture2D* texture2d = nullptr;
            wrapped_interface->GetResource(reinterpret_cast<::ID3D11Resource**>(&texture2d));
            *reinterpret_cast<wdi::ID3D11Texture2D**>(ppResource) = new texture_2d(texture2d);
        }

        ::ID3D11DepthStencilView* wrapped_interface;
    };

    class shader_resource_view : public wdi::ID3D11ShaderResourceView
    {
    public:
        shader_resource_view(::ID3D11ShaderResourceView* view) : wrapped_interface(view)
        {
            m_pResource = reinterpret_cast<wdi::ID3D11Resource*>(wrapped_interface);
            wrapped_interface->AddRef( );
        }
        IGU_DEFINE_REF

    	HRESULT QueryInterface(const IID& riid, void** ppvObject) override
        {
            if (riid == __uuidof(wdi::ID3D11ShaderResourceView))
            {
                *ppvObject = this;
                AddRef( );
                return S_OK;
            }
            TRACE_INTERFACE_NOT_HANDLED("shader_resource_view");
            *ppvObject = nullptr;
            return E_NOINTERFACE;
        }

        void STDMETHODCALLTYPE GetDesc(D3D11_SHADER_RESOURCE_VIEW_DESC* pDesc) override
        {
            wrapped_interface->GetDesc(pDesc);
        }

        void GetDevice(ID3D11Device** ppDevice) override
        {
            printf("WARN: shader_resource_view::GetDevice returns a PC device!!\n");
            wrapped_interface->GetDevice(ppDevice);
        }

        HRESULT GetPrivateData(const GUID& guid, UINT* pDataSize, void* pData) override
        {
            return wrapped_interface->GetPrivateData(guid, pDataSize, pData);
        }

        HRESULT SetPrivateData(const GUID& guid, UINT DataSize, const void* pData) override
        {
            return wrapped_interface->SetPrivateData(guid, DataSize, pData);
        }

        HRESULT SetPrivateDataInterface(const GUID& guid, const IUnknown* pData) override
        {
            return wrapped_interface->SetPrivateDataInterface(guid, pData);
        }

        HRESULT SetPrivateDataInterfaceGraphics(const GUID& guid, const IGraphicsUnknown* pData) override
        {
            TRACE_NOT_IMPLEMENTED("shader_resource_view");
            return E_NOTIMPL;
        }

        HRESULT SetName(LPCWSTR pName) override
        {
            TRACE_NOT_IMPLEMENTED("shader_resource_view");
            return E_NOTIMPL;
        }

        void GetResource(wdi::ID3D11Resource** ppResource) override
        {
            D3D11_SHADER_RESOURCE_VIEW_DESC desc;
            wrapped_interface->GetDesc(&desc);

            // FIXME: this only targets 2D textures, but it doesn't matter since all texture* classes are the same
            ::ID3D11Texture2D* texture2d = nullptr;
            wrapped_interface->GetResource(reinterpret_cast<::ID3D11Resource**>(&texture2d));
            *reinterpret_cast<wdi::ID3D11Texture2D**>(ppResource) = new texture_2d(texture2d);
        }

        ::ID3D11ShaderResourceView* wrapped_interface;
    };

    class unordered_access_view : public wdi::ID3D11UnorderedAccessView
    {
    public:
        unordered_access_view(::ID3D11UnorderedAccessView* view) : wrapped_interface(view)
        {
            m_pResource = reinterpret_cast<wdi::ID3D11Resource*>(wrapped_interface);
            wrapped_interface->AddRef( );
        }

        IGU_DEFINE_REF

    	HRESULT QueryInterface(const IID& riid, void** ppvObject) override
        {
            if (riid == __uuidof(wdi::ID3D11UnorderedAccessView))
            {
                *ppvObject = this;
                AddRef( );
                return S_OK;
            }
            TRACE_INTERFACE_NOT_HANDLED("shader_resource_view");
            *ppvObject = nullptr;
            return E_NOINTERFACE;
        }

        void STDMETHODCALLTYPE GetDesc(D3D11_UNORDERED_ACCESS_VIEW_DESC* pDesc) override
        {
            wrapped_interface->GetDesc(pDesc);
        }

        void GetDevice(ID3D11Device** ppDevice) override
        {
            printf("WARN: depth_stencil_view::GetDevice returns a PC device!!\n");
            wrapped_interface->GetDevice(ppDevice);
        }

        HRESULT GetPrivateData(const GUID& guid, UINT* pDataSize, void* pData) override
        {
            return wrapped_interface->GetPrivateData(guid, pDataSize, pData);
        }

        HRESULT SetPrivateData(const GUID& guid, UINT DataSize, const void* pData) override
        {
            return wrapped_interface->SetPrivateData(guid, DataSize, pData);
        }

        HRESULT SetPrivateDataInterface(const GUID& guid, const IUnknown* pData) override
        {
            return wrapped_interface->SetPrivateDataInterface(guid, pData);
        }

        HRESULT SetPrivateDataInterfaceGraphics(const GUID& guid, const IGraphicsUnknown* pData) override
        {
            TRACE_NOT_IMPLEMENTED("shader_resource_view");
            return E_NOTIMPL;
        }

        HRESULT SetName(LPCWSTR pName) override
        {
            TRACE_NOT_IMPLEMENTED("shader_resource_view");
            return E_NOTIMPL;
        }

        void GetResource(wdi::ID3D11Resource** ppResource) override
        {
            D3D11_UNORDERED_ACCESS_VIEW_DESC desc;
            wrapped_interface->GetDesc(&desc);

            // FIXME: this only targets 2D textures, but it doesn't matter since all texture* classes are the same
            ::ID3D11Texture2D* texture2d = nullptr;
            wrapped_interface->GetResource(reinterpret_cast<::ID3D11Resource**>(&texture2d));
            *reinterpret_cast<wdi::ID3D11Texture2D**>(ppResource) = new texture_2d(texture2d);
        }

        ::ID3D11UnorderedAccessView* wrapped_interface;
    };
}