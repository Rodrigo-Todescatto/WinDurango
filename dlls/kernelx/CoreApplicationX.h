// ReSharper disable CppInconsistentNaming
// ReSharper disable CppClassCanBeFinal
// ReSharper disable CppPolymorphicClassWithNonVirtualPublicDestructor
// ReSharper disable CppClangTidyClangDiagnosticNonVirtualDtor
#pragma once
#include <wrl/client.h>

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


private:
	winrt::Windows::ApplicationModel::Core::CoreApplication* m_applicationCore;

};