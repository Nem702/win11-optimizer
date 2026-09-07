using System.Collections.Generic;
using Win11Optimizer.Gui.Core.Contract;

namespace Win11Optimizer.Gui.Core.Process
{
    /// <summary>
    /// How a scan ended.
    /// </summary>
    /// <remarks>
    /// A SCAN THAT DIED MUST NEVER LOOK LIKE A SCAN THAT FOUND NOTHING. That is
    /// this project's signature failure mode -- docs\REVIEW.md catalogues a
    /// dozen measured instances of something returning less than the truth
    /// without erroring -- and it is the reason every way of not finishing has
    /// its own value here instead of collapsing into one "failed". Finished is
    /// exactly one of these, and it is the only one that produces a screen of
    /// rows.
    /// </remarks>
    public enum ScanOutcomeKind
    {
        /// <summary>A result line arrived and the process exited 0.</summary>
        Finished,

        /// <summary>
        /// The scan said what went wrong: an error line, and a sentence on
        /// stderr beside it. There is no result and there is no empty screen.
        /// </summary>
        ScanFailed,

        /// <summary>
        /// The process ended without writing a single line. Detectable only
        /// because a half-written result line is impossible by construction --
        /// the engine serializes it whole and writes it in one call.
        /// </summary>
        DiedWritingNothing,

        /// <summary>
        /// The process wrote progress and then stopped, with no result line and
        /// no error line. Not an empty scan: an empty scan still writes a
        /// result.
        /// </summary>
        NoResult,

        /// <summary>
        /// The stream said something this shell will not render -- a line that
        /// did not parse, an unknown kind, a schema version it does not know, a
        /// line after the terminal record, or an exit code that contradicts
        /// what was written.
        /// </summary>
        ProtocolViolation,

        /// <summary>The scan could not be started at all.</summary>
        LaunchFailed
    }

    /// <summary>What one run of the scan produced.</summary>
    public sealed class ScanOutcome
    {
        internal ScanOutcome() { }

        public ScanOutcomeKind Kind { get; internal set; }

        /// <summary>The screen, and only when Kind is Finished.</summary>
        public ResultRecord Result { get; internal set; }

        /// <summary>The engine's own error record, when it wrote one.</summary>
        public ScanErrorRecord Error { get; internal set; }

        /// <summary>
        /// One sentence saying what happened, for the failure screen. Written
        /// by this shell about its own handling of the protocol -- it is never
        /// a re-wording of anything the engine said, and where the engine said
        /// something, that text is carried beside this rather than folded into
        /// it.
        /// </summary>
        public string Message { get; internal set; }

        /// <summary>Null when the process never ran.</summary>
        public int? ExitCode { get; internal set; }

        /// <summary>
        /// Everything the scan wrote to stderr, in order. The engine puts its
        /// PARTIAL warnings here deliberately rather than leaving them to the
        /// host, so this is real information and not just noise to hide.
        /// </summary>
        public IReadOnlyList<string> StandardError { get; internal set; }

        /// <summary>How many stdout lines were read before it ended.</summary>
        public int LineCount { get; internal set; }

        public bool IsFinished
        {
            get { return Kind == ScanOutcomeKind.Finished; }
        }
    }
}
