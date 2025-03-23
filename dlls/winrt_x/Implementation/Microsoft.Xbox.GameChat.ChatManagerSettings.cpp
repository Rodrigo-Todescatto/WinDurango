#include "pch.h"
#include "Microsoft.Xbox.GameChat.ChatManagerSettings.h"
#include "Microsoft.Xbox.GameChat.ChatManagerSettings.g.cpp"

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
    uint32_t ChatManagerSettings::AudioThreadPeriodInMilliseconds()
    {
        printf("ChatManagerSettings::AudioThreadPeriodInMilliseconds\n");
        return 0;
    }
    void ChatManagerSettings::AudioThreadPeriodInMilliseconds(uint32_t value)
    {
        printf("ChatManagerSettings::AudioThreadPeriodInMilliseconds2\n");
    }
    uint32_t ChatManagerSettings::AudioThreadAffinityMask()
    {
        printf("ChatManagerSettings::AudioThreadAffinityMask\n");
        return 0;
    }
    void ChatManagerSettings::AudioThreadAffinityMask(uint32_t value)
    {
        printf("ChatManagerSettings::AudioThreadAffinityMask2\n");
    }
    int32_t ChatManagerSettings::AudioThreadPriority()
    {
        printf("ChatManagerSettings::AudioThreadPriority\n");
        return 0;
    }
    void ChatManagerSettings::AudioThreadPriority(int32_t value)
    {
        printf("ChatManagerSettings::AudioThreadPriority2\n");
    }
    winrt::Windows::Xbox::Chat::EncodingQuality ChatManagerSettings::AudioEncodingQuality()
    {
        printf("ChatManagerSettings::AudioEncodingQuality\n");
        return winrt::Windows::Xbox::Chat::EncodingQuality::High;
    }
    void ChatManagerSettings::AudioEncodingQuality(winrt::Windows::Xbox::Chat::EncodingQuality const& value)
    {
        printf("ChatManagerSettings::AudioEncodingQuality2\n");
    }
    uint32_t ChatManagerSettings::JitterBufferMaxPackets()
    {
        printf("ChatManagerSettings::JitterBufferMaxPackets\n");
        return 0;
    }
    void ChatManagerSettings::JitterBufferMaxPackets(uint32_t value)
    {
        printf("ChatManagerSettings::JitterBufferMaxPackets2\n");
    }
    uint32_t ChatManagerSettings::JitterBufferLowestNeededPacketCount()
    {
        printf("ChatManagerSettings::JitterBufferLowestNeededPacketCount\n");
        return 0;
    }
    void ChatManagerSettings::JitterBufferLowestNeededPacketCount(uint32_t value)
    {
        printf("ChatManagerSettings::JitterBufferLowestNeededPacketCount2\n");
    }
    uint32_t ChatManagerSettings::JitterBufferPacketsBeforeRelaxingNeeded()
    {
        printf("ChatManagerSettings::JitterBufferPacketsBeforeRelaxingNeeded\n");
        return 0;
    }
    void ChatManagerSettings::JitterBufferPacketsBeforeRelaxingNeeded(uint32_t value)
    {
        printf("ChatManagerSettings::JitterBufferPacketsBeforeRelaxingNeeded2\n");
    }
    bool ChatManagerSettings::PerformanceCountersEnabled()
    {
        printf("ChatManagerSettings::PerformanceCountersEnabled\n");
        return true;
    }
    void ChatManagerSettings::PerformanceCountersEnabled(bool value)
    {
        printf("ChatManagerSettings::PerformanceCountersEnabled2\n");
    }

    bool m_CombineCaptureBuffersIntoSinglePacket;
    bool ChatManagerSettings::CombineCaptureBuffersIntoSinglePacket()
    {
        return m_CombineCaptureBuffersIntoSinglePacket;
    }
    void ChatManagerSettings::CombineCaptureBuffersIntoSinglePacket(bool value)
    {
        m_CombineCaptureBuffersIntoSinglePacket = value;
    }

    bool m_UseKinectAsCaptureSource;
    bool ChatManagerSettings::UseKinectAsCaptureSource()
    {
        return m_UseKinectAsCaptureSource;
    }
    void ChatManagerSettings::UseKinectAsCaptureSource(bool value)
    {
        m_UseKinectAsCaptureSource = value;
    }

    bool m_PreEncodeCallbackEnabled;
    bool ChatManagerSettings::PreEncodeCallbackEnabled()
    {
        return m_PreEncodeCallbackEnabled;
    }
    void ChatManagerSettings::PreEncodeCallbackEnabled(bool value)
    {
        m_PreEncodeCallbackEnabled = value;
    }

    bool m_PostDecodeCallbackEnabled;
    bool ChatManagerSettings::PostDecodeCallbackEnabled()
    {
        return m_PostDecodeCallbackEnabled;
    }
    void ChatManagerSettings::PostDecodeCallbackEnabled(bool value)
    {
        m_PostDecodeCallbackEnabled = value;
    }


    winrt::Microsoft::Xbox::GameChat::GameChatDiagnosticsTraceLevel ChatManagerSettings::DiagnosticsTraceLevel()
    {

        throw hresult_not_implemented();
    }
    void ChatManagerSettings::DiagnosticsTraceLevel(winrt::Microsoft::Xbox::GameChat::GameChatDiagnosticsTraceLevel const& value)
    {
        throw hresult_not_implemented();
    }
    bool ChatManagerSettings::AutoMuteBadReputationUsers()
    {
        throw hresult_not_implemented();
    }
    void ChatManagerSettings::AutoMuteBadReputationUsers(bool value)
    {
        throw hresult_not_implemented();
    }
    uint32_t ChatManagerSettings::SessionStateUpdateRequestCoalesceDuration()
    {
        throw hresult_not_implemented();
    }
    void ChatManagerSettings::SessionStateUpdateRequestCoalesceDuration(uint32_t value)
    {
        throw hresult_not_implemented();
    }
    uint32_t ChatManagerSettings::MuteUserIfReputationIsBadCoalesceDuration()
    {
        throw hresult_not_implemented();
    }
    void ChatManagerSettings::MuteUserIfReputationIsBadCoalesceDuration(uint32_t value)
    {
        throw hresult_not_implemented();
    }
}
