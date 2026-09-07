using System;
using System.Collections.Generic;
using System.Globalization;
using Win11Optimizer.Gui.Core.Contract;
using Win11Optimizer.Gui.Core.Json;

namespace Win11Optimizer.Gui.Core.Process
{
    /// <summary>
    /// The protocol, as a state machine over the lines a scan writes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It is deliberately separate from the process that produces the lines, so
    /// every rule below can be tested by handing it strings -- no spawning, no
    /// 40-second scan, no machine state. The one thing that does need a real
    /// process boundary gets one integration test rather than making every
    /// other test pay for it.
    /// </para>
    /// <para>
    /// THE FIRST REFUSAL WINS AND IS NEVER CLEARED. Once a line has arrived
    /// that this shell will not render, nothing later can restore trust in the
    /// stream -- including a well-formed result line. Reading continues so the
    /// pipe drains and the process is not left blocked on a full buffer, but
    /// the outcome is settled.
    /// </para>
    /// </remarks>
    public sealed class ScanStream
    {
        private readonly Action<ProgressRecord> _onProgress;
        private readonly List<string> _standardError = new List<string>();

        private ResultRecord _result;
        private ScanErrorRecord _error;
        private string _refusal;
        private int _lineCount;
        private int _progressCount;

        public ScanStream() : this(null) { }

        /// <param name="onProgress">
        /// Called for each progress line as it arrives. Not wrapped in a
        /// try/catch, for the reason the engine gives about its own progress
        /// hook: a reporter that throws is the caller's defect, and swallowing
        /// it would hide a failure inside the thing that was meant to be
        /// reporting progress.
        /// </param>
        public ScanStream(Action<ProgressRecord> onProgress)
        {
            _onProgress = onProgress;
        }

        public int LineCount { get { return _lineCount; } }

        /// <summary>One line of stdout.</summary>
        public void AddLine(string line)
        {
            _lineCount++;

            if (_refusal != null)
            {
                return;
            }

            try
            {
                AddLineCore(line);
            }
            catch (ScanProtocolException ex)
            {
                _refusal = "Line " + _lineCount.ToString(CultureInfo.InvariantCulture) +
                           " of the scan output was not understood, so nothing from this run is " +
                           "shown. " + ex.Message;
            }
        }

        private void AddLineCore(string line)
        {
            if (_result != null || _error != null)
            {
                throw new ScanProtocolException(
                    "The scan wrote another line after the one that ends a run. Exactly one " +
                    "result or one error is written, and it is last.");
            }

            if (string.IsNullOrEmpty(line) || line.Trim().Length == 0)
            {
                // Not skipped. The engine writes protocol lines to stdout and
                // nothing else, so a blank line means something else got into
                // the stream -- and something else in the stream is the one
                // thing that would make the rest of it untrustworthy.
                throw new ScanProtocolException(
                    "It was blank. The scan writes one complete JSON object per line to " +
                    "standard output and nothing else.");
            }

            ScanRecord record = ScanRecordReader.Read(line);

            var progress = record as ProgressRecord;
            if (progress != null)
            {
                _progressCount++;
                if (_onProgress != null)
                {
                    _onProgress(progress);
                }

                return;
            }

            var result = record as ResultRecord;
            if (result != null)
            {
                _result = result;
                return;
            }

            _error = (ScanErrorRecord)record;
        }

        /// <summary>One line of stderr.</summary>
        public void AddErrorLine(string line)
        {
            if (line == null)
            {
                return;
            }

            _standardError.Add(line);
        }

        /// <summary>
        /// Settles the run once the process has exited. This is the only place
        /// that decides which of the ways a scan can end actually happened.
        /// </summary>
        public ScanOutcome Complete(int exitCode)
        {
            var outcome = new ScanOutcome
            {
                ExitCode = exitCode,
                StandardError = _standardError.ToArray(),
                LineCount = _lineCount
            };

            string exitText = exitCode.ToString(CultureInfo.InvariantCulture);

            // 1. A refusal outranks everything. If part of the stream was not
            //    understood, a result line elsewhere in it does not make the
            //    run readable -- it makes it a run this shell cannot vouch for.
            if (_refusal != null)
            {
                outcome.Kind = ScanOutcomeKind.ProtocolViolation;
                outcome.Message = _refusal;
                return outcome;
            }

            // 2. The scan said what went wrong. Show that, never an empty
            //    screen.
            if (_error != null)
            {
                outcome.Kind = ScanOutcomeKind.ScanFailed;
                outcome.Error = _error;
                outcome.Message =
                    "The scan stopped during the " + (_error.Phase ?? "unknown") +
                    " phase and produced no result.";

                if (exitCode == ScanContract.ExitResultWritten)
                {
                    // The engine exits 0 only when a result was written. An
                    // error line with a success code means the two halves of
                    // the contract disagree, and that is worth saying rather
                    // than quietly trusting one of them.
                    outcome.Kind = ScanOutcomeKind.ProtocolViolation;
                    outcome.Message =
                        "The scan wrote an error line but exited with code 0, which is the code " +
                        "that means a result was written. The two do not agree, so nothing from " +
                        "this run is shown.";
                }

                return outcome;
            }

            // 3. A result. It is only a screen if the exit code agrees.
            if (_result != null)
            {
                if (exitCode != ScanContract.ExitResultWritten)
                {
                    outcome.Kind = ScanOutcomeKind.ProtocolViolation;
                    outcome.Message =
                        "The scan wrote a result but exited with code " + exitText +
                        ". Exit code 0 is what says a result was written, so the two do not " +
                        "agree and nothing from this run is shown.";
                    return outcome;
                }

                outcome.Kind = ScanOutcomeKind.Finished;
                outcome.Result = _result;
                outcome.Message = null;
                return outcome;
            }

            // 4. Nothing that ends a run. These are the two shapes of a scan
            //    that stopped, and neither is an empty scan -- an empty scan
            //    still writes a result line, and would have been case 3.
            if (_lineCount == 0)
            {
                outcome.Kind = ScanOutcomeKind.DiedWritingNothing;
                outcome.Message =
                    "The scan ended with code " + exitText + " without writing anything at all. " +
                    "That is not a scan that found nothing: a scan that found nothing still " +
                    "reports what it looked at. Nothing on this PC has been read to the end, so " +
                    "nothing is shown.";
                return outcome;
            }

            outcome.Kind = ScanOutcomeKind.NoResult;
            outcome.Message =
                "The scan wrote " + _progressCount.ToString(CultureInfo.InvariantCulture) +
                " progress lines and then ended with code " + exitText +
                " without writing a result. It stopped part way through, so what it had found so " +
                "far is not shown as if it were the whole picture.";
            return outcome;
        }

        /// <summary>
        /// The scan could not be started. Kept here so that every way a run can
        /// end is described in one file.
        /// </summary>
        public static ScanOutcome LaunchFailed(string message)
        {
            return new ScanOutcome
            {
                Kind = ScanOutcomeKind.LaunchFailed,
                Message = message,
                ExitCode = null,
                StandardError = new string[0],
                LineCount = 0
            };
        }
    }
}
