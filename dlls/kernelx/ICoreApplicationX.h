// ReSharper disable CppPolymorphicClassWithNonVirtualPublicDestructor
// ReSharper disable CppInconsistentNaming
// ReSharper disable CppClangTidyClangDiagnosticNonVirtualDtor
// ReSharper disable IdentifierTypo
// ReSharper disable CppClangTidyClangDiagnosticHeaderHygiene
#include <Windows.Foundation.h>
#include <windows.applicationmodel.core.h>
#include <windows.system.h>
#include <inspectable.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/impl/Windows.ApplicationModel.core.2.h>

using namespace ABI::Windows::ApplicationModel::Activation;
using namespace ABI::Windows::ApplicationModel;
using namespace ABI::Windows::Foundation;
using namespace ABI::Windows::ApplicationModel::Core;
using namespace ABI::Windows::System;

class ICoreApplicationX : public IInspectable
{
public:
	virtual INT32 _abi_BackgroundActivated(winrt::Windows::Foundation::EventHandler<BackgroundActivatedEventArgs> const& handler) = 0;
	virtual INT32 _abi_EnteredBackground(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::EnteredBackgroundEventArgs> const& handler) = 0;
	virtual INT32 _abi_Exiting(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) = 0;
	virtual INT32 _abi_LeavingBackground(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::LeavingBackgroundEventArgs> const& handler) = 0;
	virtual INT32 _abi_Resuming(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) = 0;
	virtual INT32 _abi_Suspending(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::SuspendingEventArgs> const& handler) = 0;
	virtual INT32 _abi_UnhandledErrorDetected(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::Core::UnhandledErrorDetectedEventArgs> const& handler) = 0;

};