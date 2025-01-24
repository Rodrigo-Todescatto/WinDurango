#include "pch.h"
#include "Windows.Xbox.Management.Deployment.PackageTransferManager.h"
#include "Windows.Xbox.Management.Deployment.PackageTransferManager.g.cpp"

namespace winrt::Windows::Xbox::Management::Deployment::implementation
{
    winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Xbox::Management::Deployment::CheckForUpdateResult> PackageTransferManager::CheckForUpdateAsync(winrt::Windows::Xbox::Management::Deployment::IDownloadableContentPackage package)
    {
		printf("!!! PackageTransferManager::CheckForUpdateAsync Not Implemented !!!\n");
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Xbox::Management::Deployment::RequestUpdatePackageResult> PackageTransferManager::RequestUpdatePackageAsync(winrt::Windows::Xbox::Management::Deployment::IDownloadableContentPackage package)
    {
		printf("!!! PackageTransferManager::RequestUpdatePackageAsync Not Implemented !!!\n");
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Xbox::Management::Deployment::RequestUpdatePackageResult> PackageTransferManager::RequestUpdateCurrentPackageAsync()
    {
		printf("!!! PackageTransferManager::RequestUpdateCurrentPackageAsync Not Implemented !!!\n");
        throw hresult_not_implemented();
    }
    winrt::Windows::Xbox::Management::Deployment::PackageTransferManager PackageTransferManager::Current()
    {
        if (CurrentInstance == nullptr) {
			CurrentInstance = winrt::make<PackageTransferManager>( );
        }
		return CurrentInstance;
    }
    winrt::Windows::Xbox::Management::Deployment::PackageTransferManager PackageTransferManager::Create(winrt::Windows::ApplicationModel::Package const& package)
    {
		printf("!!! PackageTransferManager::Create Not Implemented !!!\n");
        throw hresult_not_implemented();
    }
    void PackageTransferManager::UpdateInstallOrder(winrt::Windows::Foundation::Collections::IIterable<uint32_t> const& chunkIds, winrt::Windows::Xbox::Management::Deployment::UpdateInstallOrderBehavior const& updateBehavior)
    {
		printf("!!! PackageTransferManager::UpdateInstallOrder Not Implemented !!!\n");
        throw hresult_not_implemented();
    }
    bool PackageTransferManager::IsChunkInstalled(uint32_t chunkId)
    {
        return true;
    }
    bool PackageTransferManager::AreChunksInstalled(winrt::Windows::Foundation::Collections::IIterable<uint32_t> const& chunkIds)
    {
        return true;
    }
    uint32_t PackageTransferManager::FindChunkFromFile(hstring const& path)
    {
		printf("!!! PackageTransferManager::FindChunkFromFile Not Implemented !!!\n");
        throw hresult_not_implemented();
    }
    winrt::Windows::Xbox::Management::Deployment::PackageTransferStatus PackageTransferManager::TransferStatus()
    {
		printf("!!! PackageTransferManager::TransferStatus Not Implemented !!!\n");
        throw hresult_not_implemented();
    }
    winrt::Windows::Xbox::Management::Deployment::PackageTransferType PackageTransferManager::TransferType()
    {
		printf("!!! PackageTransferManager::TransferType Not Implemented !!!\n");
        throw hresult_not_implemented();
    }
    winrt::Windows::Xbox::Management::Deployment::ChunkSpecifiers PackageTransferManager::AvailableChunkSpecifiers()
    {
		printf("!!! PackageTransferManager::AvailableChunkSpecifiers Not Implemented !!!\n");
        throw hresult_not_implemented();
    }
    winrt::Windows::Xbox::Management::Deployment::InstallationState PackageTransferManager::GetInstallationState(winrt::Windows::Foundation::Collections::IIterable<uint32_t> const& chunkIds)
    {
		printf("!!! PackageTransferManager::GetInstallationState Not Implemented !!!\n");
        throw hresult_not_implemented();
    }
    winrt::Windows::Xbox::Management::Deployment::InstallationState PackageTransferManager::GetInstallationState(winrt::Windows::Xbox::Management::Deployment::ChunkSpecifiers const& specifiers)
    {
		printf("!!! PackageTransferManager::GetInstallationState Not Implemented !!!\n");
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Xbox::Management::Deployment::PackageTransferWatcher> PackageTransferManager::AddChunkSpecifiersAsync(winrt::Windows::Xbox::Management::Deployment::ChunkSpecifiers additionalSpecifiers)
    {
		printf("!!! PackageTransferManager::AddChunkSpecifiersAsync Not Implemented !!!\n");
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::IAsyncAction PackageTransferManager::RemoveChunkSpecifiersAsync(winrt::Windows::Xbox::Management::Deployment::ChunkSpecifiers removeSpecifiers)
    {
		printf("!!! PackageTransferManager::RemoveChunkSpecifiersAsync Not Implemented !!!\n");
        throw hresult_not_implemented();
    }
}
