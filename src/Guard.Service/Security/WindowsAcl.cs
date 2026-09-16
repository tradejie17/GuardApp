using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Guard.Service.Security;

/// <summary>
/// Windows access-control helpers. Guard's resistance to being switched off rests on these:
/// the policy and the password verifier must not be writable by the standard user account that
/// is being restricted, and the pipe must be reachable by that user's browser but only
/// *readable* in the sense of sending messages the service is willing to act on.
///
/// Every member is a no-op on non-Windows platforms so the service still runs for development.
/// </summary>
public static class WindowsAcl
{
    /// <summary>
    /// Restricts a file to SYSTEM and the local Administrators group, removing inherited rights
    /// so a standard user cannot read or modify it.
    /// </summary>
    public static void RestrictToAdministrators(string path, ILogger? logger = null)
    {
        if (!OperatingSystem.IsWindows() || !File.Exists(path))
        {
            return;
        }

        try
        {
            ApplyAdminOnlyAcl(path);
        }
        catch (Exception ex)
        {
            // Losing the ACL is a hardening failure, not a functional one: log loudly and keep
            // running rather than leaving the machine unprotected entirely.
            logger?.LogError(ex, "Failed to restrict permissions on {Path}. It may be readable by standard users.", path);
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ApplyAdminOnlyAcl(string path)
    {
        var file = new FileInfo(path);
        var security = file.GetAccessControl();

        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        foreach (FileSystemAccessRule existing in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
        {
            security.RemoveAccessRule(existing);
        }

        foreach (var sid in new[]
                 {
                     new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)
                 })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                sid, FileSystemRights.FullControl, AccessControlType.Allow));
        }

        file.SetAccessControl(security);
    }

    /// <summary>
    /// Builds the pipe ACL: authenticated users may connect and exchange messages, because the
    /// native host runs in the browser's (unprivileged) session. Authorization of anything
    /// sensitive is done per-command by password, not by who can open the pipe.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static PipeSecurity CreatePipeSecurity()
    {
        var security = new PipeSecurity();

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        return security;
    }
}
