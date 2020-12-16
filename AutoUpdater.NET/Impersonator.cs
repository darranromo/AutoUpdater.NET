using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices; // DllImport
using System.Security.Principal; // WindowsImpersonationContext
using System.Security.Permissions; // PermissionSetAttribute
using System.IO;

namespace AutoUpdaterDotNET
{
    static class Impersonator
    {
        //logon impersonation

        // obtains user token
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LogonUser(string pszUsername, string pszDomain, string pszPassword,
            int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        // closes open handes returned by LogonUser
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public extern static bool CloseHandle(IntPtr handle);

        public static bool DoWorkUnderImpersonation(Func<bool> action, DomainAuthentication domainAuthentication)
        {
            if (domainAuthentication == null)
            {
                throw new Exception("Domain credentials must be provided.");
            }

            // Elevate privileges before doing file copy to handle domain security.
            WindowsImpersonationContext impersonationContext = null;
            IntPtr userHandle = IntPtr.Zero;
            const int LOGON32_PROVIDER_DEFAULT = 0;
            const int LOGON32_LOGON_INTERACTIVE = 2;

            try
            {
                // File.AppendAllText(@"C:\doc\impersonation.txt", "Windows identify before impersonation: " + WindowsIdentity.GetCurrent().Name);

                // Call LogonUser to get a token for the user
                bool loggedOn = LogonUser(domainAuthentication.Username,
                                          domainAuthentication.Domain,
                                          domainAuthentication.Password,
                                          LOGON32_LOGON_INTERACTIVE,
                                          LOGON32_PROVIDER_DEFAULT,
                                          ref userHandle);

                if (!loggedOn)
                {
                    // File.AppendAllText(@"C:\doc\impersonation.txt", "Exception impersonating user, error code: " + Marshal.GetLastWin32Error());
                    return false;
                }

                // Begin impersonating the user
                impersonationContext = WindowsIdentity.Impersonate(userHandle);

                // File.AppendAllText(@"C:\doc\impersonation.txt", "Main() windows identify after impersonation: " + WindowsIdentity.GetCurrent().Name);

                // Run the provided action using the provided user's handle.
                return action();
            }
            catch (Exception)
            {
                // File.AppendAllText(@"C:\doc\impersonation.txt", "Exception impersonating user: " + ex.Message);
                return false;
            }
            finally
            {
                // Clean up
                if (impersonationContext != null)
                {
                    impersonationContext.Undo();
                }

                if (userHandle != IntPtr.Zero)
                {
                    CloseHandle(userHandle);
                }
            }
        }
    }
}
