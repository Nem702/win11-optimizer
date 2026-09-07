using System;
using System.IO;

namespace Win11Optimizer.Gui.Core.Process
{
    /// <summary>
    /// Finding the engine, and the shell that runs it, without knowing
    /// anything about this machine.
    /// </summary>
    /// <remarks>
    /// NOTHING HERE IS A BAKED-IN PATH. Everything is resolved at run time from
    /// where the executable happens to be and from the system directory, so the
    /// binary carries no developer's folder layout and no machine name inside
    /// it -- which is an acceptance criterion for this chunk and a
    /// straightforward way to leak both.
    /// </remarks>
    public static class EngineLocation
    {
        public const string ModuleFolderName = "Win11Optimizer.Engine";
        public const string ManifestFileName = "Win11Optimizer.Engine.psd1";

        /// <summary>
        /// The launcher a second process runs. App\Scan.ps1, not Entry.ps1:
        /// Entry.ps1 starts a menu for a person, and Scan.ps1 is the
        /// machine-facing entry point.
        /// </summary>
        public static readonly string ScanScriptRelativePath =
            Path.Combine("App", "Scan.ps1");

        /// <summary>
        /// Windows PowerShell 5.1, at the fixed path it occupies on every
        /// Windows install.
        /// </summary>
        /// <remarks>
        /// It is composed rather than searched for, and 5.1 rather than
        /// whatever is on PATH, for two reasons the project has already
        /// settled: docs\REVIEW.md fixes 5.1 as the target runtime, and
        /// tests\JsonContract.Tests.ps1 takes the same fixed-path approach so
        /// that finding a shell can never be the thing that fails. PATH is not
        /// consulted, so nothing a user has installed can substitute a
        /// different interpreter.
        /// </remarks>
        public static string PowerShellPath
        {
            get
            {
                return Path.Combine(
                    Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            }
        }

        /// <summary>
        /// Walks up from a starting folder looking for the engine module beside
        /// it. Returns the module folder, or null.
        /// </summary>
        /// <remarks>
        /// One walk covers both layouts this shell runs in without either being
        /// written down: built, the executable sits several folders under
        /// src\Win11Optimizer.Gui\ and the engine is a sibling of that; and
        /// installed, both are siblings under src\. Walking up until the module
        /// appears finds it in either case, and finds nothing rather than
        /// guessing when it is not there.
        /// </remarks>
        public static string FindModuleFolder(string startFolder)
        {
            if (string.IsNullOrEmpty(startFolder))
            {
                return null;
            }

            DirectoryInfo folder;
            try
            {
                folder = new DirectoryInfo(startFolder);
            }
            catch (ArgumentException)
            {
                return null;
            }

            while (folder != null)
            {
                string candidate = Path.Combine(folder.FullName, ModuleFolderName);
                if (IsModuleFolder(candidate))
                {
                    return candidate;
                }

                // The starting folder may itself be the module folder.
                if (IsModuleFolder(folder.FullName))
                {
                    return folder.FullName;
                }

                folder = folder.Parent;
            }

            return null;
        }

        /// <summary>
        /// True when the folder holds the module manifest AND the launcher this
        /// shell runs. Both, because a folder with a manifest but no Scan.ps1
        /// is an engine too old to talk to.
        /// </summary>
        public static bool IsModuleFolder(string folder)
        {
            if (string.IsNullOrEmpty(folder))
            {
                return false;
            }

            return File.Exists(Path.Combine(folder, ManifestFileName))
                && File.Exists(Path.Combine(folder, ScanScriptRelativePath));
        }

        public static string ScanScriptPath(string moduleFolder)
        {
            if (string.IsNullOrEmpty(moduleFolder))
            {
                return null;
            }

            return Path.Combine(moduleFolder, ScanScriptRelativePath);
        }
    }
}
