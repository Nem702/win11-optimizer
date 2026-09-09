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

        /// <summary>
        /// How many objects this section inspected. The engine's own count for
        /// the scan behind the section, and it is Inventory.Count -- not
        /// Row.Count, which is only what was flagged.
        /// </summary>
        public long InventoryCount { get; internal set; }

        /// <summary>
        /// Everything the section looked at, the flagged objects included.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Row[] carries findings and nothing else. A category table has four
        /// classes and two of them -- held back by a rule, and looked at but
        /// not flagged -- are objects that produced no Finding. Before P6-C3
        /// their counts existed only inside the section's headline sentences,
        /// so the only way to draw those rows would have been to parse prose.
        /// </para>
        /// <para>
        /// A flagged entry names its row through FindingId. Drawing an entry
        /// whose class is Flagged AND its row would show the same object twice.
        /// </para>
        /// </remarks>
        public IReadOnlyList<InventoryRecord> Inventory { get; internal set; }
    }

    /// <summary>
    /// One object a section inspected, and what the engine did with it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// ABSENT IS NOT NULL HERE EITHER, and for the same reason it is not on
    /// RowRecord: an object nothing held back has no reason, and a null Reason
    /// would be a placeholder for something that does not exist. So the
    /// optional fields are Has* pairs and are bound by key presence.
    /// </para>
    /// <para>
    /// TWO OF THEM ARE TRI-STATES. TargetExists and Exists are bool? and their
    /// null is the engine saying it looked and could not tell -- a path it is
    /// not allowed to read, or a non-file action. Only false is "proved
    /// absent". A consumer that collapsed null into false would manufacture an
    /// orphan out of a permission it did not have.
    /// </para>
    /// </remarks>
    public sealed class InventoryRecord
    {
        /// <summary>
        /// The detector's own identity for the object -- a service name, a junk
        /// location id, an installed application's Id.
        /// </summary>
        /// <remarks>
        /// IT IS NOT UNIQUE ON ITS OWN, measured rather than assumed: 39 of the
        /// 289 installed-app records on the machine this was written on share
        /// an Id with another, in 17 groups. They are Appx framework packages
        /// present in more than one architecture under one package family name,
        /// and Detail -- the package full name -- separates them. A view keying
        /// rows on Id alone will collapse them.
        /// </remarks>
        public string Id { get; internal set; }

        public string DisplayName { get; internal set; }

        /// <summary>
        /// The object's own category, which is not the section's key: the
        /// StartupItems section holds both StartupItem and Service objects,
        /// because the services are among the things that start with the PC.
        /// </summary>
        public string Category { get; internal set; }

        /// <summary>
        /// Flagged, HeldBack or NotFlagged -- the engine's judgement, never
        /// this shell's. An unrecognised value is refused rather than filed
        /// under one of the three.
        /// </summary>
        public string Class { get; internal set; }

        /// <summary>True when Class is HeldBack.</summary>
        public bool IsHeldBack
        {
            get { return string.Equals(Class, ScanContract.InventoryHeldBack, System.StringComparison.Ordinal); }
        }

        /// <summary>True when Class is Flagged, in which case FindingId names its row.</summary>
        public bool IsFlagged
        {
            get { return string.Equals(Class, ScanContract.InventoryFlagged, System.StringComparison.Ordinal); }
        }

        /// <summary>
        /// Why, in the engine's words. Present where the engine had a sentence
        /// -- a curated entry's own reason, or the classifier's "Launched 4
        /// days ago, inside the 180-day window." Absent where it had none.
        /// </summary>
        public bool HasReason { get; internal set; }
        public string Reason { get; internal set; }

        /// <summary>
        /// The Finding this object went into. NOT always equal to Id: an Appx
        /// Finding is keyed on the package family name, and one curated-list
        /// Finding can cover several inventory records.
        /// </summary>
        public bool HasFindingId { get; internal set; }
        public string FindingId { get; internal set; }

        /// <summary>The curated entry that held it back.</summary>
        public bool HasRuleId { get; internal set; }
        public string RuleId { get; internal set; }

        /// <summary>
        /// That entry's class -- 'security', 'driver', 'driver-utility'. Read
        /// structurally so a view never string-matches the reason prose.
        /// </summary>
        public bool HasRuleClass { get; internal set; }
        public string RuleClass { get; internal set; }

        // ---- StartupItem and Service ----------------------------------------
        public bool HasMechanism { get; internal set; }
        public string Mechanism { get; internal set; }

        public bool HasScope { get; internal set; }
        public string Scope { get; internal set; }

        public bool HasEnabledState { get; internal set; }
        public string EnabledState { get; internal set; }

        /// <summary>Tri-state: null means it could not be determined.</summary>
        public bool HasTargetExists { get; internal set; }
        public bool? TargetExists { get; internal set; }

        // ---- StartupItem, Service and UnusedApp -----------------------------
        public bool HasPublisher { get; internal set; }
        public string Publisher { get; internal set; }

        // ---- UnusedApp -------------------------------------------------------
        public bool HasSource { get; internal set; }
        public string Source { get; internal set; }

        /// <summary>The package full name for an Appx record; the registry root for a Win32 one.</summary>
        public bool HasDetail { get; internal set; }
        public string Detail { get; internal set; }

        /// <summary>Used, Unused or Unknown -- the usage classifier's verdict, not a class.</summary>
        public bool HasState { get; internal set; }
        public string State { get; internal set; }

        // ---- JunkFile --------------------------------------------------------
        public bool HasStatus { get; internal set; }
        public string Status { get; internal set; }

        /// <summary>Tri-state: null means it could not be determined.</summary>
        public bool HasExists { get; internal set; }
        public bool? Exists { get; internal set; }

        public bool HasIsAssessed { get; internal set; }
        public bool? IsAssessed { get; internal set; }

        public bool HasFileCount { get; internal set; }
        public long? FileCount { get; internal set; }

        public bool HasTotalBytes { get; internal set; }
        public long? TotalBytes { get; internal set; }

        public bool HasEligibleFileCount { get; internal set; }
        public long? EligibleFileCount { get; internal set; }

        public bool HasEligibleBytes { get; internal set; }
        public long? EligibleBytes { get; internal set; }

        public bool HasIsSizeFloor { get; internal set; }
        public bool? IsSizeFloor { get; internal set; }

        public bool HasMinimumAgeDays { get; internal set; }
        public long? MinimumAgeDays { get; internal set; }
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
