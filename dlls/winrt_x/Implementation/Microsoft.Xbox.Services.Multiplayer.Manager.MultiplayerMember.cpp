#include "pch.h"
#include "Microsoft.Xbox.Services.Multiplayer.Manager.MultiplayerMember.h"
#include "Microsoft.Xbox.Services.Multiplayer.Manager.MultiplayerMember.g.cpp"

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
    uint32_t MultiplayerMember::MemberId()
    {
        throw hresult_not_implemented();
    }
    hstring MultiplayerMember::TeamId()
    {
        throw hresult_not_implemented();
    }
    hstring MultiplayerMember::XboxUserId()
    {
        return L"0";
    }
    hstring MultiplayerMember::DebugGamertag()
    {
        throw hresult_not_implemented();
    }
    bool MultiplayerMember::IsLocal()
    {
        throw hresult_not_implemented();
    }
    bool MultiplayerMember::IsInLobby()
    {
        throw hresult_not_implemented();
    }
    bool MultiplayerMember::IsInGame()
    {
        throw hresult_not_implemented();
    }
    winrt::Microsoft::Xbox::Services::Multiplayer::MultiplayerSessionMemberStatus MultiplayerMember::Status()
    {
        throw hresult_not_implemented();
    }
    hstring MultiplayerMember::ConnectionAddress()
    {
        throw hresult_not_implemented();
    }
    hstring MultiplayerMember::Properties()
    {
        throw hresult_not_implemented();
    }
    bool MultiplayerMember::IsMemberOnSameDevice(winrt::Microsoft::Xbox::Services::Multiplayer::Manager::MultiplayerMember const& member)
    {
        throw hresult_not_implemented();
    }
    hstring MultiplayerMember::_DeviceToken()
    {
        throw hresult_not_implemented();
    }
}
