#pragma once
#include "device_child_x.h"
#include "device_context_x.h"

namespace wdi
{
    D3DINTERFACE(ID3D11Resource, dc8e63f3, d12b, 4952, b4, 7b, 5e, 45, 02, 6a, 86, 2d) : public ID3D11DeviceChild {
	public:
        virtual void STDMETHODCALLTYPE GetType(
            /* [annotation] */
            _Out_  D3D11_RESOURCE_DIMENSION * pResourceDimension) PURE;

        virtual void STDMETHODCALLTYPE SetEvictionPriority(
            /* [annotation] */
            _In_  UINT EvictionPriority) PURE;

        virtual UINT STDMETHODCALLTYPE GetEvictionPriority(void) PURE;
        // xbox extra function
        virtual void STDMETHODCALLTYPE GetDescriptor(D3D11X_DESCRIPTOR_RESOURCE* descriptor) PURE;
    };

    D3DINTERFACE(ID3D11Texture1D, f8fb5c27, c6b3, 4f75, a4, c8, 43, 9a, f2, ef, 56, 4c) : public ID3D11Resource {
	public:
    	virtual void STDMETHODCALLTYPE GetDesc(
            /* [annotation] */
            _Out_  D3D11_TEXTURE1D_DESC* pDesc) PURE;
    };

    D3DINTERFACE(ID3D11Texture2D, 6f15aaf2, d208, 4e89, 9a, b4, 48, 95, 35, d3, 4f, 9c) : public ID3D11Resource {
	public:
        virtual void STDMETHODCALLTYPE GetDesc(
            /* [annotation] */
            _Out_  D3D11_TEXTURE2D_DESC * pDesc) PURE;
    };

    D3DINTERFACE(ID3D11Texture3D, 037e866e, f56d, 4357, a8, af, 9d, ab, be, 6e, 25, 0e) : public ID3D11Resource {
    	public:
		virtual void STDMETHODCALLTYPE GetDesc(
			/* [annotation] */
			_Out_  D3D11_TEXTURE3D_DESC* pDesc) PURE;
    };

	D3DINTERFACE(ID3D11Buffer, 48570b85, d1ee, 4fcd, a2, 50, eb, 35, 07, 22, b0, 37) : public ID3D11Resource {
		public:
		virtual void STDMETHODCALLTYPE GetDesc(
			/* [annotation] */
			_Out_  D3D11_BUFFER_DESC* pDesc) PURE;
	};
}

// @unixian: does this even need to be wrapped? seems like the only thing it does in the pre-rewrite code is handle GetDevice
namespace wd
{
	// this is only used for casting to other resources, as it's impossible to make a resource itself (has to be a texture or buffer)
	class d3d11_resource : public wdi::ID3D11Resource
	{
	public:
		void GetDevice(ID3D11Device** ppDevice) override
		{
			throw std::logic_error("Not implemented");
		}

		HRESULT GetPrivateData(const GUID& guid, UINT* pDataSize, void* pData) override
		{
			throw std::logic_error("Not implemented");
		}

		HRESULT SetPrivateData(const GUID& guid, UINT DataSize, const void* pData) override
		{
			throw std::logic_error("Not implemented");
		}

		HRESULT SetPrivateDataInterface(const GUID& guid, const IUnknown* pData) override
		{
			throw std::logic_error("Not implemented");
		}

		HRESULT SetPrivateDataInterfaceGraphics(const GUID& guid, const IGraphicsUnknown* pData) override
		{
			throw std::logic_error("Not implemented");
		}

		HRESULT SetName(LPCWSTR pName) override
		{
			throw std::logic_error("Not implemented");
		}

		void GetType(D3D11_RESOURCE_DIMENSION* pResourceDimension) override
		{
			throw std::logic_error("Not implemented");
		}

		void SetEvictionPriority(UINT EvictionPriority) override
		{
			throw std::logic_error("Not implemented");
		}

		UINT GetEvictionPriority() override
		{
			throw std::logic_error("Not implemented");
		}

		void GetDescriptor(wdi::D3D11X_DESCRIPTOR_RESOURCE* descriptor) override
		{
			throw std::logic_error("Not implemented");
		}

		::ID3D11Resource* wrapped_interface;
	};
	class texture_1d : public wdi::ID3D11Texture1D
	{
	public:
		texture_1d(::ID3D11Texture1D* texture) : wrapped_interface(texture) { wrapped_interface->AddRef( ); }

		IGU_DEFINE_REF

		HRESULT QueryInterface(const IID& riid, void** ppvObject) override
		{
			if (riid == __uuidof(wdi::ID3D11Texture1D))
			{
				*ppvObject = this;
				AddRef( );
				return S_OK;
			}

			TRACE_INTERFACE_NOT_HANDLED("texture_1d");
			*ppvObject = nullptr;
			return E_NOINTERFACE;
		}
		void STDMETHODCALLTYPE GetDesc(D3D11_TEXTURE1D_DESC* pDesc) override
		{
			wrapped_interface->GetDesc(pDesc);
		}

		void GetDevice(ID3D11Device** ppDevice) override
		{
			printf("WARN: texture_1d::GetDevice returns a PC device!!\n");
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
			TRACE_NOT_IMPLEMENTED("texture_1d");
			return E_NOTIMPL;
		}

		HRESULT SetName(LPCWSTR pName) override
		{
			TRACE_NOT_IMPLEMENTED("texture_1d");
			return E_NOTIMPL;
		}

		void GetType(D3D11_RESOURCE_DIMENSION* pResourceDimension) override
		{
			wrapped_interface->GetType(pResourceDimension);
		}

		void SetEvictionPriority(UINT EvictionPriority) override
		{
			wrapped_interface->SetEvictionPriority(EvictionPriority);
		}

		UINT GetEvictionPriority() override
		{
			return wrapped_interface->GetEvictionPriority( );
		}

		void GetDescriptor(wdi::D3D11X_DESCRIPTOR_RESOURCE* descriptor) override
		{
			TRACE_NOT_IMPLEMENTED("texture_1d");
		}

		::ID3D11Texture1D* wrapped_interface;
	};

	class texture_2d : public wdi::ID3D11Texture2D
	{
	public:
		texture_2d(::ID3D11Texture2D* texture) : wrapped_interface(texture) { wrapped_interface->AddRef( ); }

		IGU_DEFINE_REF

		HRESULT QueryInterface(const IID& riid, void** ppvObject) override
		{
			if (riid == __uuidof(wdi::ID3D11Texture2D) || riid == __uuidof(wdi::ID3D11Resource))
			{
				*ppvObject = this;
				AddRef( );
				return S_OK;
			}

			TRACE_INTERFACE_NOT_HANDLED("texture_2d");
			*ppvObject = nullptr;
			return E_NOINTERFACE;
		}

		void STDMETHODCALLTYPE GetDesc(D3D11_TEXTURE2D_DESC* pDesc) override
		{
			wrapped_interface->GetDesc(pDesc);
		}

		void GetDevice(ID3D11Device** ppDevice) override
		{
			printf("WARN: texture_2d::GetDevice returns a PC device!!\n");
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
			TRACE_NOT_IMPLEMENTED("texture_2d");
			return E_NOTIMPL;
		}

		HRESULT SetName(LPCWSTR pName) override
		{
			TRACE_NOT_IMPLEMENTED("texture_2d");
			return E_NOTIMPL;
		}

		void GetType(D3D11_RESOURCE_DIMENSION* pResourceDimension) override
		{
			wrapped_interface->GetType(pResourceDimension);
		}

		void SetEvictionPriority(UINT EvictionPriority) override
		{
			wrapped_interface->SetEvictionPriority(EvictionPriority);
		}

		UINT GetEvictionPriority( ) override
		{
			return wrapped_interface->GetEvictionPriority( );
		}

		void GetDescriptor(wdi::D3D11X_DESCRIPTOR_RESOURCE* descriptor) override
		{
			TRACE_NOT_IMPLEMENTED("texture_2d");
		}

		::ID3D11Texture2D* wrapped_interface;
	};

	class texture_3d : public wdi::ID3D11Texture3D
	{
	public:
		texture_3d(::ID3D11Texture3D* texture) : wrapped_interface(texture) { wrapped_interface->AddRef( ); }

		IGU_DEFINE_REF

		HRESULT QueryInterface(const IID& riid, void** ppvObject) override
		{
			if (riid == __uuidof(wdi::ID3D11Texture3D))
			{
				*ppvObject = this;
				AddRef( );
				return S_OK;
			}

			TRACE_INTERFACE_NOT_HANDLED("texture_3d");
			*ppvObject = nullptr;
			return E_NOINTERFACE;
		}

		void STDMETHODCALLTYPE GetDesc(D3D11_TEXTURE3D_DESC* pDesc) override
		{
			wrapped_interface->GetDesc(pDesc);
		}

		void GetDevice(ID3D11Device** ppDevice) override
		{
			printf("WARN: texture_3d::GetDevice returns a PC device!!\n");
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
			TRACE_NOT_IMPLEMENTED("texture_3d");
			return E_NOTIMPL;
		}

		HRESULT SetName(LPCWSTR pName) override
		{
			TRACE_NOT_IMPLEMENTED("texture_3d");
			return E_NOTIMPL;
		}

		void GetType(D3D11_RESOURCE_DIMENSION* pResourceDimension) override
		{
			wrapped_interface->GetType(pResourceDimension);
		}

		void SetEvictionPriority(UINT EvictionPriority) override
		{
			wrapped_interface->SetEvictionPriority(EvictionPriority);
		}

		UINT GetEvictionPriority( ) override
		{
			return wrapped_interface->GetEvictionPriority( );
		}

		void GetDescriptor(wdi::D3D11X_DESCRIPTOR_RESOURCE* descriptor) override
		{
			TRACE_NOT_IMPLEMENTED("texture_3d");
		}

		::ID3D11Texture3D* wrapped_interface;
	};

	class buffer : public wdi::ID3D11Buffer
	{
	public:
		buffer(::ID3D11Buffer* buffer) : wrapped_interface(buffer) { wrapped_interface->AddRef( ); }\

		IGU_DEFINE_REF

		HRESULT QueryInterface(const IID& riid, void** ppvObject) override
		{
			if (riid == __uuidof(wdi::ID3D11Buffer))
			{
				*ppvObject = this;
				AddRef( );
				return S_OK;
			}
			TRACE_INTERFACE_NOT_HANDLED("buffer");
			*ppvObject = nullptr;
			return E_NOINTERFACE;
		}

		void STDMETHODCALLTYPE GetDesc(D3D11_BUFFER_DESC* pDesc) override
		{
			wrapped_interface->GetDesc(pDesc);
		}

		void GetDevice(ID3D11Device** ppDevice) override
		{
			printf("WARN: buffer::GetDevice returns a PC device!!\n");
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
			TRACE_NOT_IMPLEMENTED("buffer");
			return E_NOTIMPL;
		}

		HRESULT SetName(LPCWSTR pName) override
		{
			TRACE_NOT_IMPLEMENTED("buffer");
			return E_NOTIMPL;
		}

		void GetType(D3D11_RESOURCE_DIMENSION* pResourceDimension) override
		{
			wrapped_interface->GetType(pResourceDimension);
		}

		void SetEvictionPriority(UINT EvictionPriority) override
		{
			wrapped_interface->SetEvictionPriority(EvictionPriority);
		}

		UINT GetEvictionPriority( ) override
		{
			return wrapped_interface->GetEvictionPriority( );
		}

		void GetDescriptor(wdi::D3D11X_DESCRIPTOR_RESOURCE* descriptor) override
		{
			TRACE_NOT_IMPLEMENTED("buffer");
		}

		::ID3D11Buffer* wrapped_interface;
	};
}