#include "pch.h"
#include "Microsoft.Xbox.Services.Marketplace.CatalogService.h"
#include "Microsoft.Xbox.Services.Marketplace.CatalogService.g.cpp"

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
////////static_assert(false, "This file is generated by a tool and will be overwritten. Open this error and view the comment for assistance.");

namespace winrt::Microsoft::Xbox::Services::Marketplace::implementation
{
    winrt::Windows::Foundation::IAsyncOperation<winrt::Microsoft::Xbox::Services::Marketplace::BrowseCatalogResult> CatalogService::BrowseCatalogAsync(hstring parentId, winrt::Microsoft::Xbox::Services::Marketplace::MediaItemType parentMediaType, winrt::Microsoft::Xbox::Services::Marketplace::MediaItemType childMediaType, winrt::Microsoft::Xbox::Services::Marketplace::CatalogSortOrder orderBy, uint32_t skipItems, uint32_t maxItems)
    {
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::IAsyncOperation<winrt::Microsoft::Xbox::Services::Marketplace::BrowseCatalogResult> CatalogService::BrowseCatalogBundlesAsync(hstring parentId, winrt::Microsoft::Xbox::Services::Marketplace::MediaItemType parentMediaType, hstring productId, winrt::Microsoft::Xbox::Services::Marketplace::BundleRelationshipType relationship, uint32_t skipItems, uint32_t maxItems)
    {
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Microsoft::Xbox::Services::Marketplace::CatalogItemDetails>> CatalogService::GetCatalogItemDetailsAsync(winrt::Windows::Foundation::Collections::IVectorView<hstring> productIds)
    {
        throw hresult_not_implemented();
    }
}