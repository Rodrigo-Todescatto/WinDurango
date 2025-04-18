#include "pch.h"
#include "Windows.Xbox.Storage.ContainerInfoQueryResult.h"
#include "Windows.Xbox.Storage.ContainerInfoQueryResult.g.cpp"
#include <winrt/Windows.ApplicationModel.h>
#include "../ConnectedStorage/ConnectedStorage.h"
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.Storage.FileProperties.h>
#include <winrt/Windows.Foundation.Collections.h>
#include "../ConnectedStorage/ConnectedStorage.h"

// WARNING: This file is automatically generated by a tool. Do not directly
// add this file to your project, as any changes you make will be lost.
// This file is a stub you can use as a starting point for your implementation.
//
// To add a copy of this file to your project:
//   1. Copy this file from its original location to the location where you store 
//      your other source files (e.g. the project root). 
//   2. Add the copied file to your project. In Visual Studio, you can use 
//      Project -> Add Existing Item.
//   3. Delete this comment and the 'static_assert' (below) from the copied file.
//      Do not modify the original file.
//
// To update an existing file in your project:
//   1. Copy the relevant changes from this file and merge them into the copy 
//      you made previously.
//    
// This assertion helps prevent accidental modification of generated files.
//////////

namespace winrt::Windows::Xbox::Storage::implementation
{
    winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Xbox::Storage::ContainerInfo>> ContainerInfoQueryResult::GetContainerInfoAsync(uint32_t startIndex, uint32_t maxNumberOfItems)
    {
        printf("%s called\n", __FUNCTION__);
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Xbox::Storage::ContainerInfo>> ContainerInfoQueryResult::GetContainerInfoAsync()
    {
        printf("%s called\n", __FUNCTION__);
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::IAsyncOperation<uint32_t> ContainerInfoQueryResult::GetItemCountAsync()
    {
        printf("%s called\n", __FUNCTION__);
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Xbox::Storage::ContainerInfo2>> ContainerInfoQueryResult::GetContainerInfo2Async(uint32_t startIndex, uint32_t maxNumberOfItems)
    {
        printf("%s called\n", __FUNCTION__);
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Xbox::Storage::ContainerInfo2>> ContainerInfoQueryResult::GetContainerInfo2Async()
    {

        printf("%s called\n", __FUNCTION__);
		co_return co_await m_connectedStorage->GetContainerInfo2Async();
    }
}
