using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using Win11Optimizer.Gui.Core.Contract;

namespace Win11Optimizer.Gui.Core.Process
{
    /// <summary>What to run, and how.</summary>
    public sealed class ScanRequest
    {
        /// <summary>The launcher to run. Normally App\Scan.ps1 in the engine folder.</summary>
        public string ScriptPath { get; set; }

        /// <summary>
        /// Passes -SkipPlan. Every row then arrives without its Plan, which
        /// also means without its PreviewText. The measured cost of not passing
        /// it, on this machine, elevated, was most of a 825-second run; the
        /// cost of passing it is that nothing on screen can say what would
        /// happen to a row.
        /// </summary>
        public bool SkipPlan { get; set; }

        /// <summary>Read the receipt ledger from here instead of the default. Read-only.</summary>
        public string LedgerPath { get; set; }

        /// <summary>Leave the receipt off the result entirely.</summary>
        public bool SkipReceipt { get; set; }
    }

    /// <summary>
    /// Spawns the scan and reads its output. This is the whole architecture:
    /// the shell runs the engine as a second process and renders what comes
    /// back. It decides nothing the engine has not already decided.
    /// </summary>
    public sealed class ScanProcessRunner
    {
        private readonly string _powerShellPath;

        public ScanProcessRunner() : this(EngineLocation.PowerShellPath) { }

        public ScanProcessRunner(string powerShellPath)
        {
            _powerShellPath = powerShellPath;
        }

        /// <summary>
        /// Runs one scan to completion and returns how it ended. Blocking: the
        /// caller decides which thread pays for it.
        /// </summary>
        public ScanOutcome Run(
            ScanRequest request,
            Action<ProgressRecord> onProgress,
            CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            if (!File.Exists(_powerShellPath))
            {
                return ScanStream.LaunchFailed(
                    "Windows PowerShell was not found at " + _powerShellPath +
                    ", so the scan could not be started and nothing about this PC has been read.");
            }

            if (string.IsNullOrEmpty(request.ScriptPath) || !File.Exists(request.ScriptPath))
            {
                return ScanStream.LaunchFailed(
                    "The scan launcher was not found at " + (request.ScriptPath ?? "an empty path") +
                    ", so the scan could not be started and nothing about this PC has been read.");
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = _powerShellPath,
                Arguments = BuildArguments(request),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = false,
                WorkingDirectory = Path.GetDirectoryName(request.ScriptPath) ?? string.Empty,

                // The stream is pure ASCII by construction -- the engine
                // escapes every character above 0x7E -- so this only has to
                // rule out a wide encoding, and it does. No BOM, because a BOM
                // would land in the middle of the first line.
                StandardOutputEncoding = new UTF8Encoding(false),
                StandardErrorEncoding = new UTF8Encoding(false)
            };

            var stream = new ScanStream(onProgress);

            using (var process = new System.Diagnostics.Process())
            {
                process.StartInfo = startInfo;

                try
                {
                    if (!process.Start())
                    {
                        return ScanStream.LaunchFailed(
                            "The scan process did not start, and nothing about this PC has been read.");
                    }
                }
                catch (Exception ex)
                {
                    return ScanStream.LaunchFailed(
                        "The scan process could not be started (" + ex.GetType().Name + ": " +
                        ex.Message + "), so nothing about this PC has been read.");
                }

                // STDERR IS DRAINED ON ITS OWN THREAD. Both pipes have a finite
                // buffer, and a reader that finishes one before starting the
                // other deadlocks the moment the writer fills the one nobody is
                // reading. The engine really does write to stderr -- it
                // re-emits every scan's warnings there on purpose -- so this is
                // not a theoretical pipe.
                var errorLines = new List<string>();
                var errorDone = new ManualResetEventSlim(false);
                var errorThread = new Thread(delegate ()
                {
                    try
                    {
                        string line;
                        while ((line = process.StandardError.ReadLine()) != null)
                        {
                            lock (errorLines)
                            {
                                errorLines.Add(line);
                            }
                        }
                    }
                    catch (IOException)
                    {
                        // The pipe closed under us; the exit code and stdout
                        // still say what happened.
                    }
                    finally
                    {
                        errorDone.Set();
                    }
                });

                errorThread.IsBackground = true;
                errorThread.Name = "win11-optimizer scan stderr";
                errorThread.Start();

                bool cancelled = false;

                try
                {
                    string line;
                    while ((line = process.StandardOutput.ReadLine()) != null)
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            cancelled = true;
                            break;
                        }

                        stream.AddLine(line);
                    }
                }
                catch (IOException)
                {
                    // Same as above: what was read still counts, and the
                    // outcome below is worked out from it.
                }

                if (cancelled)
                {
                    TryKill(process);
                    errorDone.Wait(TimeSpan.FromSeconds(2));

                    return ScanStream.LaunchFailed(
                        "The scan was stopped before it finished, so nothing from it is shown.");
                }

                process.WaitForExit();
                errorDone.Wait(TimeSpan.FromSeconds(2));

                lock (errorLines)
                {
                    foreach (string errorLine in errorLines)
                    {
                        stream.AddErrorLine(errorLine);
                    }
                }

                return stream.Complete(process.ExitCode);
            }
        }

        /// <summary>
        /// The command line, quoted. Exposed so a test can assert what would be
        /// run without running it.
        /// </summary>
        public static string BuildArguments(ScanRequest request)
        {
            var arguments = new StringBuilder();

            // -NoProfile, always. A profile is user-editable code that would
            // run inside the process whose stdout is a protocol stream, and one
            // Write-Host in one profile would corrupt every line after it.
            arguments.Append("-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ");
            arguments.Append(Quote(request.ScriptPath));

            if (request.SkipPlan)
            {
                arguments.Append(" -SkipPlan");
            }

            if (request.SkipReceipt)
            {
                arguments.Append(" -SkipReceipt");
            }

            if (!string.IsNullOrEmpty(request.LedgerPath))
            {
                arguments.Append(" -LedgerPath ");
                arguments.Append(Quote(request.LedgerPath));
            }

            return arguments.ToString();
        }

        private static string Quote(string value)
        {
            if (value == null)
            {
                return "\"\"";
            }

            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        private static void TryKill(System.Diagnostics.Process process)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill();
                }
            }
            catch (InvalidOperationException)
            {
            }
            catch (System.ComponentModel.Win32Exception)
            {
            }
        }
    }
}
