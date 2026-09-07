using System.Collections.Generic;

namespace Win11Optimizer.Gui.Core.Contract
{
    /// <summary>
    /// The whole decided screen. Exactly one of these arrives, last, and its
    /// arrival is what an exit code of 0 means.
    /// </summary>
    public sealed class ResultRecord : ScanRecord
    {
        /// <summary>ISO-8601 text. "" -- not null -- when the engine had no value.</summary>
        public string GeneratedUtc { get; internal set; }

        public string MachineName { get; internal set; }
        public string UserName { get; internal set; }
        public bool IsElevated { get; internal set; }

        /// <summary>
        /// False when any source of any detector was Skipped or Failed. A
        /// Refused source does not move it.
        /// </summary>
        public bool IsComplete { get; internal set; }

        /// <summary>
        /// The section TITLES that are incomplete -- named, not summarised. A
        /// banner saying "some scans were partial" without saying which would
        /// be the under-report this project exists to prevent, wearing a
        /// warning.
        /// </summary>
        public IReadOnlyList<string> PartialSection { get; internal set; }

        public long? RowCount { get; internal set; }

        /// <summary>The receipt block, or empty when the scan was asked to leave it off.</summary>
        public IReadOnlyList<string> ReceiptText { get; internal set; }

        /// <summary>One per detector, in the engine's own order.</summary>
        public IReadOnlyList<DetectorRecord> Scan { get; internal set; }

        /// <summary>The four sections, in screen order.</summary>
        public IReadOnlyList<SectionRecord> Section { get; internal set; }
    }

    /// <summary>
    /// One of the four sections. Every string on it was worded by the engine
    /// and is rendered verbatim.
    /// </summary>
    public sealed class SectionRecord
    {
        public string Key { get; internal set; }
        public string Title { get; internal set; }

        /// <summary>
        /// The section's opening sentences -- its inventory, in its own words.
        /// Each category opens differently because each one's honest first
        /// sentence is a different sentence.
        /// </summary>
        public IReadOnlyList<string> Headline { get; internal set; }

        public IReadOnlyList<string> Note { get; internal set; }

        /// <summary>
        /// Parallel to every row's Cell. The length is 5, 6 or 7: the engine
        /// splices a FindingId column into a section whose rows have colliding
        /// display names, and it does so for EVERY row of that section.
        /// </summary>
        public IReadOnlyList<string> ColumnHeader { get; internal set; }

        /// <summary>Null unless the section has rows. Only the junk section ever sets it.</summary>
        public string TotalLine { get; internal set; }

        public bool IsComplete { get; internal set; }
        public string IncompleteReason { get; internal set; }
        public IReadOnlyList<string> RefusedSourceName { get; internal set; }

        /// <summary>
        /// What to say when the section has no rows. It is never "nothing
        /// found" -- each one says what an empty list does and does not mean.
        /// </summary>
        public string EmptyText { get; internal set; }

        public long RowCount { get; internal set; }
        public IReadOnlyList<RowRecord> Row { get; internal set; }
    }

    /// <summary>One junk location's per-profile split.</summary>
    public sealed class ProfileBreakdownRecord
    {
        public string Profile { get; internal set; }
        public long? FileCount { get; internal set; }
        public long? TotalBytes { get; internal set; }
        public long? EligibleFileCount { get; internal set; }
        public long? EligibleBytes { get; internal set; }
    }

    /// <summary>
    /// What would happen to one row. The closed list the engine publishes --
    /// Step and RollbackData are deliberately not on it, because a
    /// FileDeleteSet step carries the whole eligible file list.
    /// </summary>
    public sealed class PlanRecord
    {
        public string Route { get; internal set; }
        public bool Supported { get; internal set; }
        public string UnsupportedReason { get; internal set; }
        public string CurrentState { get; internal set; }

        /// <summary>ISO-8601 text. "" -- not null -- when the engine had no value.</summary>
        public string VerifiedUtc { get; internal set; }

        public bool RequiresElevation { get; internal set; }

        /// <summary>
        /// Nullable, and never coerced. The safety rule fails closed on
        /// anything that is not a real boolean, and turning the string "false"
        /// into false here would repair the value on the way in and hide the
        /// very thing the fail-closed clause exists to catch.
        /// </summary>
        public bool? RequiresConsent { get; internal set; }

        public string SafetyLabel { get; internal set; }
        public bool IsReversible { get; internal set; }
        public IReadOnlyList<string> Note { get; internal set; }

        /// <summary>
        /// Already worded, and already asserted against the
        /// forbidden-benefit-phrase list. It is displayed; it is never
        /// re-worded, truncated to a summary, or replaced by a sentence
        /// composed from the scalars beside it.
        /// </summary>
        public IReadOnlyList<string> PreviewText { get; internal set; }
    }
}
