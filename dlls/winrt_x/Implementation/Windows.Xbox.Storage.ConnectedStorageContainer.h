#pragma once
#include "Windows.Xbox.Storage.ConnectedStorageContainer.g.h"

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
//static_assert(false, "This file is generated by a tool and will be overwritten. Open this error and view the comment for assistance.");

namespace winrt::Windows::Xbox::Storage::implementation
{
    struct ConnectedStorageContainer : ConnectedStorageContainerT<ConnectedStorageContainer>
    {
        ConnectedStorageContainer() = default;

        hstring Name();
        winrt::Windows::Xbox::Storage::ConnectedStorageSpace OwningSpace();
        winrt::Windows::Foundation::IAsyncAction SubmitUpdatesAsync(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::Streams::IBuffer> blobsToWrite, winrt::Windows::Foundation::Collections::IIterable<hstring> blobsToDelete);
        winrt::Windows::Foundation::IAsyncAction ReadAsync(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::Streams::IBuffer> blobsToRead);
        winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::Streams::IBuffer>> GetAsync(winrt::Windows::Foundation::Collections::IIterable<hstring> blobsToRead);
        winrt::Windows::Foundation::IAsyncAction SubmitPropertySetUpdatesAsync(winrt::Windows::Foundation::Collections::IPropertySet blobsToWrite, winrt::Windows::Foundation::Collections::IIterable<hstring> blobsToDelete);
        winrt::Windows::Foundation::IAsyncAction SubmitUpdatesAsync(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::Streams::IBuffer> blobsToWrite, winrt::Windows::Foundation::Collections::IIterable<hstring> blobsToDelete, hstring displayName);
        winrt::Windows::Foundation::IAsyncAction SubmitPropertySetUpdatesAsync(winrt::Windows::Foundation::Collections::IPropertySet blobsToWrite, winrt::Windows::Foundation::Collections::IIterable<hstring> blobsToDelete, hstring displayName);
        winrt::Windows::Xbox::Storage::BlobInfoQueryResult CreateBlobInfoQuery(hstring const& blobNamePrefix);
    };
}
