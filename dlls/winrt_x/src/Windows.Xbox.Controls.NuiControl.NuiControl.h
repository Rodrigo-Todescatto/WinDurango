#pragma once
#include "Windows.Xbox.Controls.NuiControl.NuiControl.g.h"

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


namespace winrt::Windows::Xbox::Controls::NuiControl::implementation
{
    struct NuiControl : NuiControlT<NuiControl>
    {
        NuiControl() = default;

        void Init(int32_t left, int32_t top, int32_t right, int32_t bottom, uint32_t consoleUserId, uint64_t defaultControllerId, winrt::Windows::Xbox::Controls::NuiControl::RenderMode const& renderMode, winrt::Windows::Xbox::Controls::NuiControl::RenderTarget const& renderTarget);
        void RenderNui();
        void Show();
        void Hide();
        void SetRenderState(winrt::Windows::Xbox::Controls::NuiControl::BioRenderState const& state);
        void SetFeedType(winrt::Windows::Xbox::Controls::NuiControl::FeedType const& feedType);
        void Unload();
        void StartStreaming();
        void StopStreaming();
        uint64_t D3dDevice();
        uint64_t D3dDeviceContext();
        int32_t DeviceStatus();
        hstring TitleText();
        bool IsWindowVisible();
        uint64_t SwapChain();
        bool IsSensorOccluded();
        bool IsFloorValid();
        bool DoesSensorNeedTilting(float& curAngleOut, float& idealAngleOut, float& heightOut, float& oldHeight, bool& valid);
        void SetGuestUserDisplayName(hstring const& displayName);
        void SelectBody(uint32_t bodyIndex, winrt::Windows::Xbox::Controls::NuiControl::ReasonToSwitch const& reasonToSwitch);
        void SelectNextUser();
        void Enroll(uint32_t consoleUserId);
        void Cancel();
        uint32_t EnrollmentErrorsForSelectedUser();
        winrt::event_token BioUIChangedEvent(winrt::Windows::Xbox::Controls::NuiControl::BioUIChangedHandler const& changeHandler);
        void BioUIChangedEvent(winrt::event_token const& cookie) noexcept;
    };
}
namespace winrt::Windows::Xbox::Controls::NuiControl::factory_implementation
{
    struct NuiControl : NuiControlT<NuiControl, implementation::NuiControl>
    {
    };
}