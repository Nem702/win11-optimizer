using System;
using System.Collections.Generic;
using System.Globalization;
using Win11Optimizer.Gui.Core.Contract;

namespace Win11Optimizer.Gui.Core.View
{
    /// <summary>One header/cell pair off a row, for the card's detail line.</summary>
    public sealed class CardDetail
    {
        internal CardDetail() { }

        public string Label { get; internal set; }
        public string Value { get; internal set; }
    }

    /// <summary>
    /// One thing that needs a decision.
    /// </summary>
    /// <remarks>
    /// Every string on this type came out of the engine. Nothing here is
    /// composed, re-worded or summarised -- the shell picks which
    /// engine-written string goes where, and that is all it does.
    /// </remarks>
    public sealed class DecisionCard
    {
        internal DecisionCard() { }

        /// <summary>
        /// Section key and row number. Row numbers are section-local, and
        /// display names really do collide -- the engine splices in a FindingId
        /// column precisely because two rows can be called "Microsoft Copilot"
        /// -- so neither the name nor the number alone identifies a card.
        /// </summary>
        public string Key { get; internal set; }

        public string SectionKey { get; internal set; }
        public string SectionTitle { get; internal set; }
        public long Number { get; internal set; }
        public string Title { get; internal set; }
        public string FindingId { get; internal set; }

        /// <summary>The engine's resolved label, verbatim. One of exactly two strings.</summary>
        public string SafetyLabel { get; internal set; }

        /// <summary>
        /// True only when the label is the engine's "safe" string, and false
        /// for anything else at all.
        /// </summary>
        /// <remarks>
        /// This is the console's rule, kept identical rather than reinvented:
        /// Get-ReviewSafetyStyle maps the first label to the safe style and
        /// EVERYTHING ELSE to the review style. It fails closed, so a label
        /// this shell has never seen is presented as needing review rather than
        /// as safe. Nothing here re-derives the label itself -- the rule that
        /// produced it is a scriptblock that stayed in the engine on purpose.
        /// </remarks>
        public bool IsSafe { get; internal set; }

        /// <summary>
        /// The card's reason line: the cell under the section's "Why flagged"
        /// column where the section has one, and the first line of the row's
        /// evidence where it does not. The junk section has no reason column --
        /// its rows are sized, not argued -- so its cards read their reason off
        /// the evidence the detector wrote.
        /// </summary>
        public string LeadLine { get; internal set; }

        public IReadOnlyList<string> Evidence { get; internal set; }

        /// <summary>The row's remaining cells under their own column headings.</summary>
        public IReadOnlyList<CardDetail> Detail { get; internal set; }

        /// <summary>
        /// The plan's own words for what would happen, verbatim, or empty when
        /// the scan was run without planning. Never re-worded, never truncated
        /// to a summary, never replaced by a sentence composed from the scalars
        /// beside it.
        /// </summary>
        public IReadOnlyList<string> PreviewText { get; internal set; }

        public bool HasPlan { get; internal set; }
        public bool IsReversible { get; internal set; }
        public bool RequiresElevation { get; internal set; }
        public bool? RequiresConsent { get; internal set; }
        public string Route { get; internal set; }

        /// <summary>
        /// False when the engine says this row's plan is not supported. The
        /// shell does not work out what is actionable; it reads Plan.Supported
        /// and holds back what the engine already refused.
        /// </summary>
        public bool IsSelectable { get; internal set; }

        /// <summary>The engine's UnsupportedReason, when it held the row back.</summary>
        public string HeldBackReason { get; internal set; }
    }

    /// <summary>
    /// One line of the inventory strip: what a section looked at, in the
    /// section's own words.
    /// </summary>
    public sealed class InventoryRow
    {
        internal InventoryRow() { }

        public string SectionKey { get; internal set; }
        public string Title { get; internal set; }

        /// <summary>The section's first headline. Its inventory sentence, verbatim.</summary>
        public string Lead { get; internal set; }

        /// <summary>The rest of the headlines, verbatim.</summary>
        public IReadOnlyList<string> Detail { get; internal set; }

        /// <summary>How many rows of this section are in the queue.</summary>
        public long DecisionCount { get; internal set; }

        /// <summary>
        /// What the engine says an empty list means here, when the section has
        /// no rows. It is never "nothing found": each section says what an
        /// empty list does and does not prove.
        /// </summary>
        public string EmptyText { get; internal set; }

        public bool IsComplete { get; internal set; }
        public string IncompleteReason { get; internal set; }

        /// <summary>The section's own notes, verbatim.</summary>
        public IReadOnlyList<string> Note { get; internal set; }
    }

    /// <summary>A source that was not read, and why.</summary>
    public sealed class SourceNote
    {
        internal SourceNote() { }

        public string Detector { get; internal set; }
        public string Name { get; internal set; }
        public string Status { get; internal set; }
        public string Reason { get; internal set; }
    }

    /// <summary>
    /// The decisions screen: the queue, and the inventory it came out of.
    /// </summary>
    /// <remarks>
    /// THE INVENTORY IS NOT A FOOTNOTE. It sits directly under the queue at the
    /// same weight, because the thesis of this tool is that it refuses to guess
    /// and says so -- and a decision queue on its own is one design slip from
    /// reading like something that has already made up its mind.
    /// </remarks>
    public sealed class DecisionsView
    {
        private const string WhyFlaggedHeader = "Why flagged";
        private const string NumberHeader = "#";
        private const string SafetyHeader = "Safety";

        private DecisionsView() { }

        public string MachineName { get; private set; }
        public string UserName { get; private set; }
        public string GeneratedUtc { get; private set; }
        public bool IsElevated { get; private set; }

        public bool IsComplete { get; private set; }

        /// <summary>
        /// The section TITLES that are incomplete. Named, never summarised: a
        /// banner saying "some scans were partial" without saying which would
        /// be the under-report this project exists to prevent, wearing a
        /// warning.
        /// </summary>
        public IReadOnlyList<string> PartialSection { get; private set; }

        public IReadOnlyList<DecisionCard> Card { get; private set; }
        public IReadOnlyList<InventoryRow> Inventory { get; private set; }

        /// <summary>Sources that were Skipped or Failed. These make the scan incomplete.</summary>
        public IReadOnlyList<SourceNote> Incomplete { get; private set; }

        /// <summary>
        /// Sources this project refuses to use at all, on any machine, at any
        /// privilege level. Kept apart from the incomplete ones on purpose: a
        /// refusal is a design decision and reporting it as a failure would be
        /// wrong in a way that flatters the tool.
        /// </summary>
        public IReadOnlyList<SourceNote> Refused { get; private set; }

        /// <summary>
        /// True when the scan ran without planning, so no card can say what
        /// would happen and nothing is held back for being unsupported. The
        /// screen says this rather than letting the absence read as "everything
        /// is actionable".
        /// </summary>
        public bool PlansWereSkipped { get; private set; }

        public static DecisionsView Build(ResultRecord result)
        {
            if (result == null)
            {
                throw new ArgumentNullException("result");
            }

            var view = new DecisionsView
            {
                MachineName = result.MachineName,
                UserName = result.UserName,
                GeneratedUtc = result.GeneratedUtc,
                IsElevated = result.IsElevated,
                IsComplete = result.IsComplete,
                PartialSection = result.PartialSection
            };

            var cards = new List<DecisionCard>();
            var inventory = new List<InventoryRow>();
            int rowsSeen = 0;
            int rowsWithPlan = 0;

            // Section order is the engine's, and row order within a section is
            // the engine's Number. Neither is re-sorted here: the order the
            // four sections appear in is a decision docs\STATE.md made about
            // which honest first sentence comes first.
            foreach (SectionRecord section in result.Section)
            {
                foreach (RowRecord row in section.Row)
                {
                    rowsSeen++;
                    if (row.HasPlan)
                    {
                        rowsWithPlan++;
                    }

                    cards.Add(BuildCard(section, row));
                }

                inventory.Add(BuildInventoryRow(section));
            }

            var incomplete = new List<SourceNote>();
            var refused = new List<SourceNote>();

            foreach (DetectorRecord detector in result.Scan)
            {
                foreach (SourceRecord source in detector.Source)
                {
                    var note = new SourceNote
                    {
                        Detector = detector.Detector,
                        Name = source.Name,
                        Status = source.Status,
                        Reason = source.Reason
                    };

                    if (source.MakesScanIncomplete)
                    {
                        incomplete.Add(note);
                    }
                    else if (source.Status == ScanContract.StatusRefused)
                    {
                        refused.Add(note);
                    }
                }
            }

            view.Card = cards;
            view.Inventory = inventory;
            view.Incomplete = incomplete;
            view.Refused = refused;

            // Only a scan with rows can show that none of them was planned.
            // With no rows at all there is nothing to conclude either way, and
            // claiming plans were skipped would be an invention.
            view.PlansWereSkipped = rowsSeen > 0 && rowsWithPlan == 0;

            return view;
        }

        private static DecisionCard BuildCard(SectionRecord section, RowRecord row)
        {
            PlanRecord plan = row.Plan;

            var card = new DecisionCard
            {
                Key = section.Key + "#" + row.Number.ToString(CultureInfo.InvariantCulture),
                SectionKey = section.Key,
                SectionTitle = section.Title,
                Number = row.Number,
                Title = row.DisplayName,
                FindingId = row.FindingId,
                SafetyLabel = row.SafetyLabel,
                IsSafe = string.Equals(
                    row.SafetyLabel, ScanContract.SafetyLabelSafe, StringComparison.Ordinal),
                Evidence = row.Evidence,
                HasPlan = row.HasPlan && plan != null,
                PreviewText = plan != null ? plan.PreviewText : (IReadOnlyList<string>)new string[0],
                IsReversible = plan != null && plan.IsReversible,
                RequiresElevation = plan != null && plan.RequiresElevation,
                RequiresConsent = row.RequiresConsent,
                Route = plan != null ? plan.Route : null
            };

            string why = CellUnder(section, row, WhyFlaggedHeader);
            if (string.IsNullOrEmpty(why) && row.Evidence.Count > 0)
            {
                why = row.Evidence[0];
            }

            card.LeadLine = why;
            card.Detail = BuildDetail(section, row);

            if (plan != null && !plan.Supported)
            {
                card.IsSelectable = false;
                card.HeldBackReason = plan.UnsupportedReason;
            }
            else
            {
                card.IsSelectable = true;
                card.HeldBackReason = null;
            }

            return card;
        }

        /// <summary>
        /// The row's cells under their headings, minus the three that are
        /// already somewhere else on the card: the row number, the display name
        /// and the safety label. Positional, because that is how the engine
        /// builds them -- and the column count is not fixed, since a section
        /// whose display names collide gets a FindingId column spliced into
        /// every one of its rows.
        /// </summary>
        private static IReadOnlyList<CardDetail> BuildDetail(SectionRecord section, RowRecord row)
        {
            var detail = new List<CardDetail>();
            int last = section.ColumnHeader.Count - 1;

            for (int i = 0; i < section.ColumnHeader.Count && i < row.Cell.Count; i++)
            {
                if (i == 0 || i == 1 || i == last)
                {
                    continue;
                }

                string header = section.ColumnHeader[i];
                if (string.Equals(header, WhyFlaggedHeader, StringComparison.Ordinal))
                {
                    continue;
                }

                if (string.Equals(header, NumberHeader, StringComparison.Ordinal) ||
                    string.Equals(header, SafetyHeader, StringComparison.Ordinal))
                {
                    continue;
                }

                string value = row.Cell[i];
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }

                detail.Add(new CardDetail { Label = header, Value = value });
            }

            return detail;
        }

        private static string CellUnder(SectionRecord section, RowRecord row, string header)
        {
            for (int i = 0; i < section.ColumnHeader.Count && i < row.Cell.Count; i++)
            {
                if (string.Equals(section.ColumnHeader[i], header, StringComparison.Ordinal))
                {
                    return row.Cell[i];
                }
            }

            return null;
        }

        private static InventoryRow BuildInventoryRow(SectionRecord section)
        {
            string lead = section.Headline.Count > 0 ? section.Headline[0] : section.Title;

            var rest = new List<string>();
            for (int i = 1; i < section.Headline.Count; i++)
            {
                rest.Add(section.Headline[i]);
            }

            return new InventoryRow
            {
                SectionKey = section.Key,
                Title = section.Title,
                Lead = lead,
                Detail = rest,
                DecisionCount = section.Row.Count,
                EmptyText = section.Row.Count == 0 ? section.EmptyText : null,
                IsComplete = section.IsComplete,
                IncompleteReason = section.IncompleteReason,
                Note = section.Note
            };
        }
    }
}
