// ReSharper disable CppInconsistentNaming
// ReSharper disable CppClassCanBeFinal
// ReSharper disable CppPolymorphicClassWithNonVirtualPublicDestructor
// ReSharper disable CppClangTidyClangDiagnosticNonVirtualDtor
#pragma once
#include <wrl/client.h>

#include <winrt/windows.foundation.collections.h>
#include "ICoreApplicationX.h"


class CoreApplicationX : public ICoreApplicationX
{
public:
	CoreApplicationX(winrt::Windows::ApplicationModel::Core::CoreApplication* application)
	{
		m_applicationCore = reinterpret_cast<winrt::Windows::ApplicationModel::Core::CoreApplication*>(application);
	}

public:
	INT32 _abi_BackgroundActivated(winrt::Windows::Foundation::EventHandler<BackgroundActivatedEventArgs> const& handler) override;
	INT32 _abi_EnteredBackground(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::EnteredBackgroundEventArgs> const& handler) override;
	INT32 _abi_Exiting(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) override;
	INT32 _abi_LeavingBackground(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::LeavingBackgroundEventArgs> const& handler) override;
	INT32 _abi_Resuming(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) override;
	INT32 _abi_Suspending(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::SuspendingEventArgs> const& handler) override;
	INT32 _abi_UnhandledErrorDetected(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::Core::UnhandledErrorDetectedEventArgs> const& handler) override;

	INT32 _abi_RequestRestartAsync(winrt::hstring const& launchArguments) override;
	INT32 _abi_RequestRestartForUserAsync(winrt::Windows::System::User const& user, winrt::hstring const& launchArguments) override;
	INT32 _abi_IncrementApplicationUseCount() override;
	INT32 _abi_DecrementApplicationUseCount() override;
	INT32 _abi_RunWithActivationFactories(winrt::Windows::Foundation::IGetActivationFactory const& activationFactoryCallback) override;
	INT32 _abi_CreateNewView() override;
	INT32 _abi_GetCurrentView() override;
	INT32 _abi_EnablePrelaunch(bool const& value) override;
	INT32 _abi_Run(winrt::Windows::ApplicationModel::Core::IFrameworkViewSource const& viewSource) override;
	INT32 _abi_Exit() override;

private:
	winrt::Windows::ApplicationModel::Core::CoreApplication* m_applicationCore;

};