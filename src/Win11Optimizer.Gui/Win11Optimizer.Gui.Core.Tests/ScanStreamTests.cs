using System.Collections.Generic;
using Win11Optimizer.Gui.Core.Contract;
using Win11Optimizer.Gui.Core.Process;
using Xunit;

namespace Win11Optimizer.Gui.Core.Tests
{
    /// <summary>
    /// A scan that died must never look like a scan that found nothing.
    /// </summary>
    /// <remarks>
    /// Every test here is one of the ways a run can end, and the last one is
    /// the reason all the others exist: a scan that genuinely found nothing has
    /// its own outcome, and no failure can be mistaken for it.
    /// </remarks>
    public class ScanStreamTests
    {
        [Fact]
        public void A_result_and_exit_zero_is_the_only_way_to_get_a_screen()
        {
            var stream = new ScanStream();
            stream.AddLine(Fixture.Progress(ScanContract.PhaseStartupItems, 1));
            stream.AddLine(Fixture.GoldenResult());

            ScanOutcome outcome = stream.Complete(0);

            Assert.Equal(ScanOutcomeKind.Finished, outcome.Kind);
            Assert.True(outcome.IsFinished);
            Assert.NotNull(outcome.Result);
            Assert.Null(outcome.Message);
        }

        [Fact]
        public void A_non_zero_exit_with_an_error_line_shows_the_error_and_not_an_empty_screen()
        {
            var stream = new ScanStream();
            stream.AddLine(Fixture.Progress(ScanContract.PhaseJunkFiles, 3));
            stream.AddLine(Fixture.Error(
                "JunkFiles", "UnauthorizedAccessException", "Access to the path is denied."));
            stream.AddErrorLine(
                "win11-optimizer: the scan failed during the JunkFiles phase and no result was produced.");

            ScanOutcome outcome = stream.Complete(1);

            Assert.Equal(ScanOutcomeKind.ScanFailed, outcome.Kind);
            Assert.Null(outcome.Result);

            Assert.NotNull(outcome.Error);
            Assert.Equal("JunkFiles", outcome.Error.Phase);
            Assert.Equal("UnauthorizedAccessException", outcome.Error.ExceptionType);
            Assert.Equal("Access to the path is denied.", outcome.Error.Message);

            // The engine's stderr sentence is carried beside the record rather
            // than folded into it.
            Assert.Single(outcome.StandardError);
        }

        [Fact]
        public void A_process_that_died_writing_nothing_is_detected_and_said_so()
        {
            var stream = new ScanStream();

            ScanOutcome outcome = stream.Complete(1);

            Assert.Equal(ScanOutcomeKind.DiedWritingNothing, outcome.Kind);
            Assert.Equal(0, outcome.LineCount);
            Assert.Contains("without writing anything at all", outcome.Message);

            // The distinction stated in the message, not just in the enum.
            Assert.Contains("not a scan that found nothing", outcome.Message);
        }

        [Fact]
        public void Progress_and_then_nothing_is_not_an_empty_scan()
        {
            var stream = new ScanStream();
            stream.AddLine(Fixture.Progress(ScanContract.PhaseStartupItems, 1));
            stream.AddLine(Fixture.Progress(ScanContract.PhaseInstalledApps, 2));

            ScanOutcome outcome = stream.Complete(1);

            Assert.Equal(ScanOutcomeKind.NoResult, outcome.Kind);
            Assert.Contains("2 progress lines", outcome.Message);
            Assert.Contains("without writing a result", outcome.Message);
        }

        [Fact]
        public void Exit_zero_with_no_result_line_is_a_violation_and_not_an_empty_screen()
        {
            var stream = new ScanStream();
            stream.AddLine(Fixture.Progress(ScanContract.PhaseStartupItems, 1));

            ScanOutcome outcome = stream.Complete(0);

            Assert.Equal(ScanOutcomeKind.NoResult, outcome.Kind);
            Assert.Null(outcome.Result);
        }

        [Fact]
        public void A_line_that_does_not_parse_stops_the_run_and_names_the_line()
        {
            var stream = new ScanStream();
            stream.AddLine(Fixture.Progress(ScanContract.PhaseStartupItems, 1));
            stream.AddLine("WARNING: PARTIAL -- one folder could not be listed.");
            stream.AddLine(Fixture.GoldenResult());

            ScanOutcome outcome = stream.Complete(0);

            // A good result line later does not restore trust in a stream that
            // already had something else in it.
            Assert.Equal(ScanOutcomeKind.ProtocolViolation, outcome.Kind);
            Assert.Null(outcome.Result);
            Assert.Contains("Line 2", outcome.Message);
            Assert.Contains("not valid JSON", outcome.Message);
        }

        [Fact]
        public void A_blank_line_is_refused_rather_than_skipped()
        {
            var stream = new ScanStream();
            stream.AddLine(string.Empty);

            ScanOutcome outcome = stream.Complete(0);

            Assert.Equal(ScanOutcomeKind.ProtocolViolation, outcome.Kind);
            Assert.Contains("It was blank.", outcome.Message);
        }

        [Fact]
        public void A_line_after_the_terminal_record_is_a_violation()
        {
            var stream = new ScanStream();
            stream.AddLine(Fixture.GoldenResult());
            stream.AddLine(Fixture.Progress(ScanContract.PhaseAssembling, 5));

            ScanOutcome outcome = stream.Complete(0);

            Assert.Equal(ScanOutcomeKind.ProtocolViolation, outcome.Kind);
            Assert.Contains("another line after the one that ends a run", outcome.Message);
        }

        [Fact]
        public void A_result_with_a_non_zero_exit_code_is_a_violation()
        {
            var stream = new ScanStream();
            stream.AddLine(Fixture.GoldenResult());

            ScanOutcome outcome = stream.Complete(1);

            Assert.Equal(ScanOutcomeKind.ProtocolViolation, outcome.Kind);
            Assert.Contains("exited with code 1", outcome.Message);
        }

        [Fact]
        public void An_error_line_with_a_success_exit_code_is_a_violation()
        {
            var stream = new ScanStream();
            stream.AddLine(Fixture.Error("Import", "ImportFailed", "Could not load the engine."));

            ScanOutcome outcome = stream.Complete(0);

            Assert.Equal(ScanOutcomeKind.ProtocolViolation, outcome.Kind);
            Assert.Contains("exited with code 0", outcome.Message);
        }

        [Fact]
        public void The_launcher_import_failure_reads_even_though_its_phase_is_not_one_of_the_five()
        {
            // App\Scan.ps1 writes this as a hard-coded constant when the module
            // will not import, before anything that knows about phases exists.
            var stream = new ScanStream();
            stream.AddLine(
                "{\"kind\":\"error\",\"schemaVersion\":1,\"timestamp\":\"2026-09-06T12:00:00.0000000Z\"," +
                "\"Phase\":\"Import\",\"ExceptionType\":\"ImportFailed\"," +
                "\"Message\":\"win11-optimizer could not load its engine module. " +
                "The reason is on stderr.\"}");
            stream.AddErrorLine("win11-optimizer: the engine module could not be imported.");

            ScanOutcome outcome = stream.Complete(1);

            Assert.Equal(ScanOutcomeKind.ScanFailed, outcome.Kind);
            Assert.Equal("Import", outcome.Error.Phase);
        }

        [Fact]
        public void A_scan_that_found_nothing_still_produces_a_screen()
        {
            // THE TEST THE OTHERS EXIST FOR. An empty scan is not any of the
            // failures above: it wrote a result, it exited 0, and it has
            // something to say about what it looked at.
            var stream = new ScanStream();
            stream.AddLine(Fixture.EmptyResult());

            ScanOutcome outcome = stream.Complete(0);

            Assert.Equal(ScanOutcomeKind.Finished, outcome.Kind);
            Assert.NotNull(outcome.Result);
            Assert.Empty(outcome.Result.Section);
            Assert.Equal(0, outcome.Result.RowCount);

            Assert.NotEqual(ScanOutcomeKind.DiedWritingNothing, outcome.Kind);
            Assert.NotEqual(ScanOutcomeKind.NoResult, outcome.Kind);
        }

        [Fact]
        public void Progress_records_reach_the_caller_as_they_arrive()
        {
            var seen = new List<ProgressRecord>();
            var stream = new ScanStream(seen.Add);

            stream.AddLine(Fixture.Progress(ScanContract.PhaseStartupItems, 1));
            stream.AddLine(Fixture.Progress(ScanContract.PhaseInstalledApps, 2));
            stream.AddLine(Fixture.GoldenResult());

            Assert.Equal(2, seen.Count);
            Assert.Equal(ScanContract.PhaseStartupItems, seen[0].Phase);
            Assert.Equal(ScanContract.PhaseInstalledApps, seen[1].Phase);
        }

        [Fact]
        public void A_launch_failure_is_its_own_outcome_with_no_exit_code()
        {
            ScanOutcome outcome = ScanStream.LaunchFailed("The scan launcher was not found.");

            Assert.Equal(ScanOutcomeKind.LaunchFailed, outcome.Kind);
            Assert.Null(outcome.ExitCode);
            Assert.Null(outcome.Result);
            Assert.Equal(0, outcome.LineCount);
        }
    }
}
