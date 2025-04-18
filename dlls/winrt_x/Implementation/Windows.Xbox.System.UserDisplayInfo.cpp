#include "pch.h"
#include "Windows.Xbox.System.UserDisplayInfo.h"
#include "Windows.Xbox.System.UserDisplayInfo.g.cpp"

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
////

namespace winrt::Windows::Xbox::System::implementation
{
    hstring UserDisplayInfo::Gamertag( )
    {
        hstring gamertag = L"durangler" + m_gamertag;
        return gamertag;
    }
    uint32_t UserDisplayInfo::GamerScore( )
    {
        printf("!!!!! Windows.Xbox.System.UserDisplayInfo [GamerScore] NOT IMPLEMENTED !!!!\n");
        return 0;
    }
    hstring UserDisplayInfo::ApplicationDisplayName( )
    {
        printf("!!!!! Windows.Xbox.System.UserDisplayInfo [ApplicationDisplayName] NOT IMPLEMENTED !!!!\n");
        return winrt::to_hstring("WinDurango");
    }
    hstring UserDisplayInfo::GameDisplayName( )
    {
        hstring gamertag = L"durangler" + m_gamertag;
        return gamertag;
    }
    int32_t UserDisplayInfo::Reputation( )
    {
        printf("!!!!! Windows.Xbox.System.UserDisplayInfo [Reputation] NOT IMPLEMENTED !!!!\n");
        return 1;
    }
    winrt::Windows::Xbox::System::UserAgeGroup UserDisplayInfo::AgeGroup( )
    {
        return UserAgeGroup::Adult;
    }
    winrt::Windows::Foundation::Collections::IVectorView<uint32_t> UserDisplayInfo::Privileges( )
    {
        printf("!!!!! Windows.Xbox.System.UserDisplayInfo [Privileges] NOT IMPLEMENTED !!!!\n");

        auto vector = winrt::single_threaded_vector<uint32_t>( );
        vector.Append(1);
        return vector.GetView( );
    }
}