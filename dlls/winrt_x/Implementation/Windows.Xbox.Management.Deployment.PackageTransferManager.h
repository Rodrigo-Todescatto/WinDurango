#pragma once
#include "Windows.Xbox.Management.Deployment.PackageTransferManager.g.h"

namespace winrt::Windows::Xbox::Management::Deployment::implementation
{
    struct PackageTransferManager : PackageTransferManagerT<PackageTransferManager>
    {
        PackageTransferManager() = default;

        static winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Xbox::Management::Deployment::CheckForUpdateResult> CheckForUpdateAsync(winrt::Windows::Xbox::Management::Deployment::IDownloadableContentPackage package);
        static winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Xbox::Management::Deployment::RequestUpdatePackageResult> RequestUpdatePackageAsync(winrt::Windows::Xbox::Management::Deployment::IDownloadableContentPackage package);
        static winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Xbox::Management::Deployment::RequestUpdatePackageResult> RequestUpdateCurrentPackageAsync();
        static winrt::Windows::Xbox::Management::Deployment::PackageTransferManager Current();
        static winrt::Windows::Xbox::Management::Deployment::PackageTransferManager Create(winrt::Windows::ApplicationModel::Package const& package);
        void UpdateInstallOrder(winrt::Windows::Foundation::Collections::IIterable<uint32_t> const& chunkIds, winrt::Windows::Xbox::Management::Deployment::UpdateInstallOrderBehavior const& updateBehavior);
        bool IsChunkInstalled(uint32_t chunkId);
        bool AreChunksInstalled(winrt::Windows::Foundation::Collections::IIterable<uint32_t> const& chunkIds);
        uint32_t FindChunkFromFile(hstring const& path);
        winrt::Windows::Xbox::Management::Deployment::PackageTransferStatus TransferStatus();
        winrt::Windows::Xbox::Management::Deployment::PackageTransferType TransferType();
        winrt::Windows::Xbox::Management::Deployment::ChunkSpecifiers AvailableChunkSpecifiers();
        winrt::Windows::Xbox::Management::Deployment::InstallationState GetInstallationState(winrt::Windows::Foundation::Collections::IIterable<uint32_t> const& chunkIds);
        winrt::Windows::Xbox::Management::Deployment::InstallationState GetInstallationState(winrt::Windows::Xbox::Management::Deployment::ChunkSpecifiers const& specifiers);
        winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Xbox::Management::Deployment::PackageTransferWatcher> AddChunkSpecifiersAsync(winrt::Windows::Xbox::Management::Deployment::ChunkSpecifiers additionalSpecifiers);
        winrt::Windows::Foundation::IAsyncAction RemoveChunkSpecifiersAsync(winrt::Windows::Xbox::Management::Deployment::ChunkSpecifiers removeSpecifiers);
		inline static winrt::Windows::Xbox::Management::Deployment::PackageTransferManager CurrentInstance = {nullptr};
    };
}
namespace winrt::Windows::Xbox::Management::Deployment::factory_implementation
{
    struct PackageTransferManager : PackageTransferManagerT<PackageTransferManager, implementation::PackageTransferManager>
    {
    };
}
