#include "pch.h"
#include "Windows.Xbox.Storage.ConnectedStorageContainer.h"
#include "Windows.Xbox.Storage.ConnectedStorageContainer.g.cpp"
#include "../ConnectedStorage/ConnectedStorage.h"
#include <shlobj.h>
#include <strsafe.h>
#include <winrt/Windows.Storage.Streams.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <robuffer.h>
#include "Windows.Xbox.Storage.BlobInfoQueryResult.h"
#include <iostream>

using namespace Windows::Storage::Streams;

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
//

namespace winrt::Windows::Xbox::Storage::implementation
{
    hstring ConnectedStorageContainer::Name()
    {
        printf("%s called\n", __FUNCTION__);
		return containerName;
    }
    winrt::Windows::Xbox::Storage::ConnectedStorageSpace ConnectedStorageContainer::OwningSpace()
    {
        printf("%s called\n", __FUNCTION__);
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::IAsyncAction ConnectedStorageContainer::SubmitUpdatesAsync(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::Streams::IBuffer> blobsToWrite, winrt::Windows::Foundation::Collections::IIterable<hstring> blobsToDelete)
    {
        printf("%s called\n", __FUNCTION__);
        co_await m_connectedStorage->Upload(Name( ), blobsToWrite, blobsToDelete);
    }
    winrt::Windows::Foundation::IAsyncAction ConnectedStorageContainer::ReadAsync(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::Streams::IBuffer> blobsToRead)
    {
        printf("%s called\n", __FUNCTION__);
        co_await m_connectedStorage->Read(Name( ), blobsToRead);
    }
    winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::Streams::IBuffer>> ConnectedStorageContainer::GetAsync(winrt::Windows::Foundation::Collections::IIterable<hstring> blobsToRead)
    {
        printf("%s called\n", __FUNCTION__);
        if (!co_await m_connectedStorage->DoesFolderExist(L"\\" + containerName)) {
            co_await m_connectedStorage->CreateContainer(containerName);
            printf("[ConnectedStorage] Container %S created\n", containerName.c_str( ));
        }

        winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::Storage::Streams::IBuffer> data;
        auto folder = co_await winrt::Windows::Storage::StorageFolder::GetFolderFromPathAsync(L"\\" + containerName);

        for (auto const& blobs : blobsToRead)
        {
            auto fileName = blobs;
            auto file = co_await folder.GetFileAsync(fileName);
            auto fileBuffer = co_await winrt::Windows::Storage::FileIO::ReadBufferAsync(file);
            data.Insert(fileName, fileBuffer);
            co_await m_connectedStorage->Read(Name( ), data.GetView( ));
        }

        co_return data.GetView();
    }
    winrt::Windows::Foundation::IAsyncAction ConnectedStorageContainer::SubmitPropertySetUpdatesAsync(winrt::Windows::Foundation::Collections::IPropertySet blobsToWrite, winrt::Windows::Foundation::Collections::IIterable<hstring> blobsToDelete)
    {
        printf("%s called\n", __FUNCTION__);
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::IAsyncAction ConnectedStorageContainer::SubmitUpdatesAsync(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::Streams::IBuffer> blobsToWrite, winrt::Windows::Foundation::Collections::IIterable<hstring> blobsToDelete, hstring displayName)
    {
        printf("%s called\n", __FUNCTION__);
        co_await m_connectedStorage->Upload(Name(), blobsToWrite, blobsToDelete, displayName);
    }
    winrt::Windows::Foundation::IAsyncAction ConnectedStorageContainer::SubmitPropertySetUpdatesAsync(winrt::Windows::Foundation::Collections::IPropertySet blobsToWrite, winrt::Windows::Foundation::Collections::IIterable<hstring> blobsToDelete, hstring displayName)
    {
        printf("%s called\n", __FUNCTION__);
        throw hresult_not_implemented();
    }
    winrt::Windows::Xbox::Storage::BlobInfoQueryResult ConnectedStorageContainer::CreateBlobInfoQuery(hstring const& blobNamePrefix)
    {
        printf("%s called\n", __FUNCTION__);
        return winrt::make<winrt::Windows::Xbox::Storage::implementation::BlobInfoQueryResult>(Name(), blobNamePrefix, m_connectedStorage);
    }
}
