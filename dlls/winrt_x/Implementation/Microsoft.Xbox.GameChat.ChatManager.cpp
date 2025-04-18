#include "pch.h"
#include "Microsoft.Xbox.GameChat.ChatManager.h"
#include "Microsoft.Xbox.GameChat.ChatManager.g.cpp"

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

namespace winrt::Microsoft::Xbox::GameChat::implementation
{
    ChatManager::ChatManager(winrt::Microsoft::Xbox::GameChat::ChatSessionPeriod const& chatSessionPeriod)
    {
        throw hresult_not_implemented();
    }
    ChatManager::ChatManager(winrt::Microsoft::Xbox::GameChat::ChatSessionPeriod const& chatSessionPeriod, bool titleEnforcedPrivilegeAndPrivacy)
    {
        throw hresult_not_implemented();
    }
    ChatManager::ChatManager(winrt::Microsoft::Xbox::GameChat::ChatSessionPeriod const& chatSessionPeriod, winrt::Microsoft::Xbox::GameChat::PrivilegeAndPrivacyEnforcementMode const& privilegeAndPrivacyEnforcementMode, winrt::Microsoft::Xbox::GameChat::TextConversionMode const& textConversionMode)
    {
        throw hresult_not_implemented();
    }
    winrt::Microsoft::Xbox::GameChat::ChatManagerSettings ChatManager::ChatSettings()
    {
        return winrt::make<ChatManagerSettings>( );
    }
    winrt::event_token ChatManager::OnDebugMessage(winrt::Windows::Foundation::EventHandler<winrt::Microsoft::Xbox::GameChat::DebugMessageEventArgs> const& __param0)
    {
        return {};
    }
    void ChatManager::OnDebugMessage(winrt::event_token const& __param0) noexcept
    {

    }
    winrt::event_token ChatManager::OnOutgoingChatPacketReady(winrt::Windows::Foundation::EventHandler<winrt::Microsoft::Xbox::GameChat::ChatPacketEventArgs> const& __param0)
    {
        return {};
    }
    void ChatManager::OnOutgoingChatPacketReady(winrt::event_token const& __param0) noexcept
    {
        throw hresult_not_implemented();
    }
    winrt::event_token ChatManager::OnCompareUniqueConsoleIdentifiers(winrt::Microsoft::Xbox::GameChat::CompareUniqueConsoleIdentifiersHandler const& __param0)
    {
        return {};
    }
    void ChatManager::OnCompareUniqueConsoleIdentifiers(winrt::event_token const& __param0) noexcept
    {

    }
    winrt::event_token ChatManager::OnUserAddedToChannel(winrt::Windows::Foundation::EventHandler<winrt::Microsoft::Xbox::GameChat::ChannelUpdatedEventArgs> const& __param0)
    {
        return {};
    }
    void ChatManager::OnUserAddedToChannel(winrt::event_token const& __param0) noexcept
    {

    }
    winrt::event_token ChatManager::OnUserRemovedFromChannel(winrt::Windows::Foundation::EventHandler<winrt::Microsoft::Xbox::GameChat::ChannelUpdatedEventArgs> const& __param0)
    {
        return {};
    }
    void ChatManager::OnUserRemovedFromChannel(winrt::event_token const& __param0) noexcept
    {

    }
    winrt::event_token ChatManager::OnPreEncodeAudioBuffer(winrt::Microsoft::Xbox::GameChat::ProcessAudioBufferHandler const& __param0)
    {
        return {};
    }
    void ChatManager::OnPreEncodeAudioBuffer(winrt::event_token const& __param0) noexcept
    {

    }
    winrt::event_token ChatManager::OnPostDecodeAudioBuffer(winrt::Microsoft::Xbox::GameChat::ProcessAudioBufferHandler const& __param0)
    {
        return {};
    }
    void ChatManager::OnPostDecodeAudioBuffer(winrt::event_token const& __param0) noexcept
    {

    }
    winrt::event_token ChatManager::OnTextMessageReceived(winrt::Windows::Foundation::EventHandler<winrt::Microsoft::Xbox::GameChat::TextMessageReceivedEventArgs> const& __param0)
    {
        return {};
    }
    void ChatManager::OnTextMessageReceived(winrt::event_token const& __param0) noexcept
    {

    }
    winrt::event_token ChatManager::OnAccessibilitySettingsChanged(winrt::Windows::Foundation::EventHandler<winrt::Microsoft::Xbox::GameChat::AccessibilitySettingsChangedEventArgs> const& __param0)
    {
        return {};
    }
    void ChatManager::OnAccessibilitySettingsChanged(winrt::event_token const& __param0) noexcept
    {

    }
    winrt::Microsoft::Xbox::GameChat::ChatMessageType ChatManager::ProcessIncomingChatMessage(winrt::Windows::Storage::Streams::IBuffer const& chatPacket, winrt::Windows::Foundation::IInspectable const& uniqueRemoteConsoleIdentifier)
    {
        throw hresult_not_implemented( );
    }
    void ChatManager::HandleNewRemoteConsole(winrt::Windows::Foundation::IInspectable const& uniqueRemoteConsoleIdentifier)
    {

    }
    winrt::Windows::Foundation::IAsyncAction ChatManager::AddLocalUserToChatChannelAsync(uint8_t channelIndex, winrt::Windows::Xbox::System::IUser user)
    {
        throw hresult_not_implemented( );
    }
    winrt::Windows::Foundation::IAsyncAction ChatManager::AddLocalUsersToChatChannelAsync(uint8_t channelIndex, winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Xbox::System::User> users)
    {
        throw hresult_not_implemented( );
    }
    winrt::Windows::Foundation::IAsyncAction ChatManager::RemoveLocalUserFromChatChannelAsync(uint8_t channelIndex, winrt::Windows::Xbox::System::IUser user)
    {
        co_return;
    }
    winrt::Windows::Foundation::IAsyncAction ChatManager::RemoveRemoteConsoleAsync(winrt::Windows::Foundation::IInspectable uniqueRemoteConsoleIdentifier)
    {
        throw hresult_not_implemented();
    }
    winrt::Windows::Foundation::Collections::IVectorView<winrt::Microsoft::Xbox::GameChat::ChatUser> ChatManager::GetChatUsers()
    {
		return winrt::single_threaded_vector<winrt::Microsoft::Xbox::GameChat::ChatUser>( ).GetView();
    }
    void ChatManager::MuteUserFromAllChannels(winrt::Microsoft::Xbox::GameChat::ChatUser const& user)
    {

    }
    void ChatManager::UnmuteUserFromAllChannels(winrt::Microsoft::Xbox::GameChat::ChatUser const& user)
    {

    }
    void ChatManager::MuteAllUsersFromAllChannels()
    {

    }
    void ChatManager::UnmuteAllUsersFromAllChannels()
    {

    }
    winrt::Windows::Foundation::IAsyncAction ChatManager::MuteUserIfReputationIsBadAsync(winrt::Microsoft::Xbox::GameChat::ChatUser user)
    {
        throw hresult_not_implemented();
    }
    bool ChatManager::HasMicFocus()
    {
        return true;
    }
    winrt::Microsoft::Xbox::GameChat::ChatPerformanceCounters ChatManager::ChatPerformanceCounters()
    {
        throw hresult_not_implemented();
    }
}
