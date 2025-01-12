#include "pch.h"
#include "Windows.Kinect.BodyFrameSource.h"
#include "Windows.Kinect.BodyFrameSource.g.cpp"

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
////static_assert(false, "This file is generated by a tool and will be overwritten. Open this error and view the comment for assistance.");

namespace winrt::Windows::Kinect::implementation
{
    winrt::event_token BodyFrameSource::FrameCaptured(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Kinect::BodyFrameSource, winrt::Windows::Kinect::FrameCapturedEventArgs> const& value)
    {
        throw hresult_not_implemented();
    }
    void BodyFrameSource::FrameCaptured(winrt::event_token const& token) noexcept
    {
        throw hresult_not_implemented();
    }
    bool BodyFrameSource::IsActive()
    {
        throw hresult_not_implemented();
    }
    int32_t BodyFrameSource::BodyCount()
    {
        throw hresult_not_implemented();
    }
    winrt::Windows::Kinect::BodyFrameReader BodyFrameSource::OpenReader()
    {
        throw hresult_not_implemented();
    }
    winrt::Windows::Kinect::KinectSensor BodyFrameSource::KinectSensor()
    {
        throw hresult_not_implemented();
    }
    void BodyFrameSource::OverrideHandTracking(uint64_t trackingId)
    {
        throw hresult_not_implemented();
    }
    void BodyFrameSource::OverrideHandTracking(uint64_t oldTrackingId, uint64_t newTrackingId)
    {
        throw hresult_not_implemented();
    }
}