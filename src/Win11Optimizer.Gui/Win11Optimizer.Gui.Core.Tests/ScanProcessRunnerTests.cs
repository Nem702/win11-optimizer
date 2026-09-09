using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using Win11Optimizer.Gui.Core.Contract;
using Win11Optimizer.Gui.Core.Process;
using Xunit;

namespace Win11Optimizer.Gui.Core.Tests
{
    /// <summary>
    /// The one place a real process boundary is paid for.
    /// </summary>
    /// <remarks>
    /// Everything about the protocol is tested against strings in
    /// ScanStreamTests, which costs nothing. These tests exist for what a
    /// string cannot prove: that a real second process is spawned, that its
    /// stdout is read line by line, that its stderr is drained without
    /// deadlocking, and that its exit code arrives. They drive a stub script
    /// rather than the real scan, so they take milliseconds instead of the 39
    /// seconds a real un-elevated run takes.
    /// </remarks>
    public class ScanProcessRunnerTests : IDisposable
    {
        private readonly string _folder;

        public ScanProcessRunnerTests()
        {
            _folder = Path.Combine(Path.GetTempPath(), "w11o-gui-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_folder);
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(_folder, true);
            }
            catch (IOException)
            {
            }
        }

        /// <summary>
        /// Writes a stub launcher. Everything it emits goes through
        /// [Console]::Out with an explicit LF, exactly as Review\Json.ps1's
        /// writer does -- Write-Output would put objects on the pipeline for
        /// the host to format.
        /// </summary>
        private string Stub(string body)
        {
            string path = Path.Combine(_folder, "Stub.ps1");
            File.WriteAllText(path, body, new UTF8Encoding(false));
            return path;
        }

        private static ScanOutcome Run(string scriptPath, Action<ProgressRecord> onProgress = null)
        {
            return new ScanProcessRunner().Run(
                new ScanRequest { ScriptPath = scriptPath },
                onProgress,
                CancellationToken.None);
        }

        private static string Emit(string json)
        {
            return "[Console]::Out.Write('" + json.Replace("'", "''") + "' + \"`n\")\n";
        }

        [Fact]
        public void Windows_powershell_is_where_it_always_is()
        {
            Assert.True(File.Exists(EngineLocation.PowerShellPath), EngineLocation.PowerShellPath);

            // Case-insensitively: Windows reports its own system directory as
            // "system32" here and as "System32" elsewhere, and neither is this
            // shell's business.
            Assert.EndsWith(
                @"System32\WindowsPowerShell\v1.0\powershell.exe",
                EngineLocation.PowerShellPath,
                StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void A_real_process_writes_lines_that_become_a_screen()
        {
            string script =
                Emit(Fixture.Progress(ScanContract.PhaseStartupItems, 1)) +
                Emit(Fixture.GoldenResult()) +
                "exit 0\n";

            var seen = new List<ProgressRecord>();
            ScanOutcome outcome = Run(Stub(script), seen.Add);

            Assert.Equal(ScanOutcomeKind.Finished, outcome.Kind);
            Assert.Equal(0, outcome.ExitCode);
            Assert.Equal(2, outcome.LineCount);
            Assert.Single(seen);
            Assert.Equal(5, outcome.Result.RowCount);
        }

        [Fact]
        public void A_real_process_that_exits_one_after_an_error_line_reports_the_error_and_the_stderr_sentence()
        {
            string script =
                Emit(Fixture.Error("JunkFiles", "UnauthorizedAccessException", "Access is denied.")) +
                "[Console]::Error.WriteLine('win11-optimizer: the scan failed during the JunkFiles phase.')\n" +
                "exit 1\n";

            ScanOutcome outcome = Run(Stub(script));

            Assert.Equal(ScanOutcomeKind.ScanFailed, outcome.Kind);
            Assert.Equal(1, outcome.ExitCode);
            Assert.Equal("UnauthorizedAccessException", outcome.Error.ExceptionType);
            Assert.Contains(outcome.StandardError, l => l.Contains("the scan failed during"));
        }

        [Fact]
        public void A_real_process_that_writes_nothing_is_detected_as_such()
        {
            ScanOutcome outcome = Run(Stub("exit 1\n"));

            Assert.Equal(ScanOutcomeKind.DiedWritingNothing, outcome.Kind);
            Assert.Equal(0, outcome.LineCount);
            Assert.Equal(1, outcome.ExitCode);
        }

        [Fact]
        public void Stderr_large_enough_to_fill_a_pipe_buffer_does_not_deadlock_the_run()
        {
            // Both pipes have a finite buffer. A reader that finished stdout
            // before starting stderr would hang here rather than fail, which is
            // the worst way for this to be wrong.
            string script =
                "1..400 | ForEach-Object { [Console]::Error.WriteLine('win11-optimizer: warning ' + $_ + \" " +
                new string('x', 200) + "\") }\n" +
                Emit(Fixture.GoldenResult()) +
                "exit 0\n";

            ScanOutcome outcome = Run(Stub(script));

            Assert.Equal(ScanOutcomeKind.Finished, outcome.Kind);
            Assert.Equal(400, outcome.StandardError.Count);
        }

        [Fact]
        public void A_launcher_that_is_not_there_is_a_launch_failure_and_not_an_empty_scan()
        {
            ScanOutcome outcome = Run(Path.Combine(_folder, "NotHere.ps1"));

            Assert.Equal(ScanOutcomeKind.LaunchFailed, outcome.Kind);
            Assert.Null(outcome.ExitCode);
            Assert.Contains("nothing about this PC has been read", outcome.Message);
        }

        [Fact]
        public void Non_ascii_would_survive_the_pipe_if_the_engine_ever_sent_any()
        {
            // The engine escapes everything above 0x7E, so this can only be
            // belt and braces -- but it is the encoding of the pipe that is
            // being checked, and getting that wrong would corrupt a payload
            // silently rather than loudly.
            string script =
                Emit("{\"kind\":\"progress\",\"schemaVersion\":1,\"timestamp\":\"2026-09-06T12:00:00Z\"," +
                     "\"Phase\":\"JunkFiles\",\"PhaseIndex\":3,\"PhaseCount\":5," +
                     "\"Message\":\"Measuring \\u00e9clair.\",\"Item\":\"\\u4e2d\",\"ItemIndex\":1," +
                     "\"ItemCount\":2,\"FindingCount\":0,\"InventoryCount\":0}") +
                Emit(Fixture.GoldenResult()) +
                "exit 0\n";

            var seen = new List<ProgressRecord>();
            ScanOutcome outcome = Run(Stub(script), seen.Add);

            Assert.Equal(ScanOutcomeKind.Finished, outcome.Kind);
            Assert.Equal("Measuring \u00e9clair.", seen[0].Message);
            Assert.Equal("\u4e2d", seen[0].Item);
        }

        // ---- the command line, without running it -------------------------------

        [Fact]
        public void The_command_line_never_loads_a_profile()
        {
            // A profile is user-editable code that would run inside the process
            // whose stdout is a protocol stream. One Write-Host in one profile
            // corrupts every line after it.
            string arguments = ScanProcessRunner.BuildArguments(
                new ScanRequest { ScriptPath = @"C:\somewhere\Scan.ps1" });

            Assert.StartsWith("-NoProfile ", arguments);
            Assert.Contains("-NonInteractive", arguments);
            Assert.Contains("-File \"C:\\somewhere\\Scan.ps1\"", arguments);
        }

        [Fact]
        public void Skip_plan_is_passed_through_only_when_asked_for()
        {
            var request = new ScanRequest { ScriptPath = @"C:\x\Scan.ps1" };

            Assert.DoesNotContain("-SkipPlan", ScanProcessRunner.BuildArguments(request));

            request.SkipPlan = true;
            Assert.Contains(" -SkipPlan", ScanProcessRunner.BuildArguments(request));
        }

        [Fact]
        public void A_path_with_a_space_in_it_is_quoted()
        {
            string arguments = ScanProcessRunner.BuildArguments(
                new ScanRequest { ScriptPath = @"C:\Program Files\win11-optimizer\App\Scan.ps1" });

            Assert.Contains("\"C:\\Program Files\\win11-optimizer\\App\\Scan.ps1\"", arguments);
        }

        // ---- finding the engine --------------------------------------------------

        [Fact]
        public void The_engine_is_found_by_walking_up_rather_than_by_a_compiled_in_path()
        {
            string engine = Path.Combine(_folder, "src", EngineLocation.ModuleFolderName);
            Directory.CreateDirectory(Path.Combine(engine, "App"));
            File.WriteAllText(Path.Combine(engine, EngineLocation.ManifestFileName), "@{}");
            File.WriteAllText(Path.Combine(engine, "App", "Scan.ps1"), "exit 0");

            string deep = Path.Combine(_folder, "src", "Win11Optimizer.Gui", "bin", "Release", "net48");
            Directory.CreateDirectory(deep);

            Assert.Equal(engine, EngineLocation.FindModuleFolder(deep));
        }

        [Fact]
        public void A_module_folder_without_the_launcher_is_not_accepted()
        {
            // A manifest with no App\Scan.ps1 beside it is an engine too old to
            // talk to, and running it would fail in a less obvious way.
            string engine = Path.Combine(_folder, EngineLocation.ModuleFolderName);
            Directory.CreateDirectory(engine);
            File.WriteAllText(Path.Combine(engine, EngineLocation.ManifestFileName), "@{}");

            Assert.False(EngineLocation.IsModuleFolder(engine));
            Assert.Null(EngineLocation.FindModuleFolder(_folder));
        }

        [Fact]
        public void The_real_engine_in_this_repository_is_found_from_the_test_assembly()
        {
            string engine = EngineLocation.FindModuleFolder(
                Path.Combine(Fixture.RepoRoot(), "src", "Win11Optimizer.Gui"));

            Assert.NotNull(engine);
            Assert.True(File.Exists(EngineLocation.ScanScriptPath(engine)));
        }
    }
}
