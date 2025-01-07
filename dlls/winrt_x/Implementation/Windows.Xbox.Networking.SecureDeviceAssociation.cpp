#include "pch.h"
#include "Windows.Xbox.Networking.SecureDeviceAssociation.h"
#include "Windows.Xbox.Networking.SecureDeviceAssociation.g.cpp"

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

namespace winrt::Windows::Xbox::Networking::implementation
{
    winrt::Windows::Xbox::Networking::SecureDeviceAssociation SecureDeviceAssociation::GetAssociationBySocketAddressBytes(array_view<uint8_t const> remoteSocketAddressBytes, array_view<uint8_t const> localSocketAddressBytes)
    {
        throw hresult_not_implemented();
    }
    winrt::Windows::Xbox::Networking::SecureDeviceAssociation SecureDeviceAssociation::GetAssociationByHostNamesAndPorts(winrt::Windows::Networking::HostName const& remoteHostName, hstring const& remotePort, winrt::Windows::Networking::HostName const& localHostName, hstring const& localPort)
    {
        throw hresult_not_implemented();
    }
    winrt::event_token SecureDeviceAssociation::StateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Xbox::Networking::SecureDeviceAssociation, winrt::Windows::Xbox::Networking::SecureDeviceAssociationStateChangedEventArgs> const& handler)
    {
        throw hresult_not_implemented();
    }
    void SecureDeviceAssociation::StateChanged(winrt::event_token const& token) noexcept
    {
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::IAsyncAction SecureDeviceAssociation::DestroyAsync()
    {
        throw hresult_not_implemented();
    }
    void SecureDeviceAssociation::GetRemoteSocketAddressBytes(array_view<uint8_t> socketAddressBytes)
    {
        throw hresult_not_implemented();
    }
    void SecureDeviceAssociation::GetLocalSocketAddressBytes(array_view<uint8_t> socketAddressBytes)
    {
        throw hresult_not_implemented();
    }
    winrt::Windows::Xbox::Networking::SecureDeviceAssociationState SecureDeviceAssociation::State()
    {
        throw hresult_not_implemented();
    }
    winrt::Windows::Xbox::Networking::SecureDeviceAssociationTemplate SecureDeviceAssociation::Template()
    {
        throw hresult_not_implemented();
    }
    winrt::Windows::Xbox::Networking::SecureDeviceAddress SecureDeviceAssociation::RemoteSecureDeviceAddress()
    {
        throw hresult_not_implemented();
    }
    winrt::Windows::Networking::HostName SecureDeviceAssociation::RemoteHostName()
    {
        throw hresult_not_implemented();
    }
    hstring SecureDeviceAssociation::RemotePort()
    {
        throw hresult_not_implemented();
    }
    winrt::Windows::Networking::HostName SecureDeviceAssociation::LocalHostName()
    {
        throw hresult_not_implemented();
    }
    hstring SecureDeviceAssociation::LocalPort()
    {
        throw hresult_not_implemented();
    }
}