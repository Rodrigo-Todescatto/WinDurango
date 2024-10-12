// ReSharper disable CppInconsistentNaming
// ReSharper disable CppFunctionResultShouldBeUsed
// ReSharper disable CppParameterMayBeConst
#include "pch.h"
#include <winrt/windows.foundation.collections.h>
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

INT32 CoreApplicationX::_abi_RequestRestartAsync(winrt::hstring const& launchArguments)
{
	return m_applicationCore->RequestRestartAsync(launchArguments);
}

INT32 CoreApplicationX::_abi_RequestRestartForUserAsync(winrt::Windows::System::User const& user, winrt::hstring const& launchArguments)
{
	return m_applicationCore->RequestRestartForUserAsync(user, launchArguments);
}

INT32 CoreApplicationX::_abi_IncrementApplicationUseCount()
{
	return m_applicationCore->IncrementApplicationUseCount();
}

INT32 CoreApplicationX::_abi_DecrementApplicationUseCount()
{
	return m_applicationCore->DecrementApplicationUseCount();
}

INT32 CoreApplicationX::_abi_RunWithActivationFactories(winrt::Windows::Foundation::IGetActivationFactory const& activationFactoryCallback)
{
	return m_applicationCore->RunWithActivationFactories(activationFactoryCallback);
}

INT32 CoreApplicationX::_abi_CreateNewView()
{
	return m_applicationCore->CreateNewView();
}

INT32 CoreApplicationX::_abi_GetCurrentView()
{
	return m_applicationCore->GetCurrentView();
}

INT32 CoreApplicationX::_abi_EnablePrelaunch(bool const& value)
{
	return m_applicationCore->EnablePrelaunch(value);
}

INT32 CoreApplicationX::_abi_Run(winrt::Windows::ApplicationModel::Core::IFrameworkViewSource const& viewSource)
{
	return m_applicationCore->Run(viewSource);
}

INT32 CoreApplicationX::_abi_Exit()
{
	return m_applicationCore->Exit();
}