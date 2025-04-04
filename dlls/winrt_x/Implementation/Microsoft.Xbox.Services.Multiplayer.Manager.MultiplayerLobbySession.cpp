#include "pch.h"
#include "Microsoft.Xbox.Services.Multiplayer.Manager.MultiplayerLobbySession.h"
#include "Microsoft.Xbox.Services.Multiplayer.Manager.MultiplayerLobbySession.g.cpp"

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
////////

namespace winrt::Microsoft::Xbox::Services::Multiplayer::Manager::implementation
{
    hstring MultiplayerLobbySession::CorrelationId()
    {
        throw hresult_not_implemented();
    }
    winrt::Microsoft::Xbox::Services::Multiplayer::MultiplayerSessionReference MultiplayerLobbySession::SessionReference()
    {
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::Collections::IVectorView<winrt::Microsoft::Xbox::Services::Multiplayer::Manager::MultiplayerMember> MultiplayerLobbySession::LocalMembers()
    {
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::Collections::IVectorView<winrt::Microsoft::Xbox::Services::Multiplayer::Manager::MultiplayerMember> MultiplayerLobbySession::Members()
    {
        throw hresult_not_implemented();
    }
    winrt::Microsoft::Xbox::Services::Multiplayer::Manager::MultiplayerMember MultiplayerLobbySession::Host()
    {
        throw hresult_not_implemented();
    }
    hstring MultiplayerLobbySession::Properties()
    {
        throw hresult_not_implemented();
    }
    winrt::Microsoft::Xbox::Services::Multiplayer::MultiplayerSessionConstants MultiplayerLobbySession::SessionConstants()
    {
        throw hresult_not_implemented();
    }
    winrt::Microsoft::Xbox::Services::Tournaments::TournamentTeamResult MultiplayerLobbySession::LastTournamentTeamResult()
    {
        throw hresult_not_implemented();
    }
    void MultiplayerLobbySession::AddLocalUser(winrt::Windows::Xbox::System::User const& user)
    {
        throw hresult_not_implemented();
    }
    void MultiplayerLobbySession::RemoveLocalUser(winrt::Windows::Xbox::System::User const& user)
    {
        throw hresult_not_implemented();
    }
    void MultiplayerLobbySession::SetLocalMemberProperties(winrt::Windows::Xbox::System::User const& user, hstring const& name, hstring const& valueJson, winrt::Windows::Foundation::IInspectable const& context)
    {
        throw hresult_not_implemented();
    }
    void MultiplayerLobbySession::DeleteLocalMemberProperties(winrt::Windows::Xbox::System::User const& user, hstring const& name, winrt::Windows::Foundation::IInspectable const& context)
    {
        throw hresult_not_implemented();
    }
    void MultiplayerLobbySession::SetLocalMemberConnectionAddress(winrt::Windows::Xbox::System::User const& user, hstring const& connectionAddress, winrt::Windows::Foundation::IInspectable const& context)
    {
        throw hresult_not_implemented();
    }
    bool MultiplayerLobbySession::IsHost(hstring const& xboxUserId)
    {
        throw hresult_not_implemented();
    }
    void MultiplayerLobbySession::SetProperties(hstring const& name, hstring const& valueJson, winrt::Windows::Foundation::IInspectable const& context)
    {
        throw hresult_not_implemented();
    }
    void MultiplayerLobbySession::SetSynchronizedProperties(hstring const& name, hstring const& valueJson, winrt::Windows::Foundation::IInspectable const& context)
    {
        throw hresult_not_implemented();
    }
    void MultiplayerLobbySession::SetSynchronizedHost(winrt::Microsoft::Xbox::Services::Multiplayer::Manager::MultiplayerMember const& gameHost, winrt::Windows::Foundation::IInspectable const& context)
    {
        throw hresult_not_implemented();
    }
    void MultiplayerLobbySession::InviteFriends(winrt::Windows::Xbox::System::User const& user, hstring const& contextStringId, hstring const& customActivationContext)
    {
        throw hresult_not_implemented();
    }
    void MultiplayerLobbySession::InviteUsers(winrt::Windows::Xbox::System::User const& user, winrt::Windows::Foundation::Collections::IVectorView<hstring> const& xboxUserIds, hstring const& contextStringId, hstring const& customActivationContext)
    {
        throw hresult_not_implemented();
    }
}
