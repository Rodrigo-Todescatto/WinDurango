// ReSharper disable CppInconsistentNaming
// ReSharper disable CppFunctionResultShouldBeUsed
// ReSharper disable CppParameterMayBeConst
#include "pch.h"
#include "CoreApplicationX.h"

INT32 CoreApplicationX::_abi_BackgroundActivated(winrt::Windows::Foundation::EventHandler<BackgroundActivatedEventArgs> const& handler)
{
	return m_applicationCore->BackgroundActivated(handler);
}

INT32 CoreApplicationX::_abi_EnteredBackground(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::EnteredBackgroundEventArgs> const& handler)
{
	return m_applicationCore->EnteredBackground(handler);
}

INT32 CoreApplicationX::_abi_Exiting(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
{
	return m_applicationCore->Exiting(handler);
}

INT32 CoreApplicationX::_abi_LeavingBackground(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::LeavingBackgroundEventArgs> const& handler)
{
	return m_applicationCore->LeavingBackground(handler);
}

INT32 CoreApplicationX::_abi_Resuming(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
{
	return m_applicationCore->Resuming(handler);
}

INT32 CoreApplicationX::_abi_Suspending(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::SuspendingEventArgs> const& handler)
{
	return m_applicationCore->Suspending(handler);
}

INT32 CoreApplicationX::_abi_UnhandledErrorDetected(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::Core::UnhandledErrorDetectedEventArgs> const& handler)
{
	return m_applicationCore->UnhandledErrorDetected(handler);
}