using System.Linq;
using Win11Optimizer.Gui.Core.Contract;
using Win11Optimizer.Gui.Core.Json;
using Win11Optimizer.Gui.Core.View;
using Xunit;

namespace Win11Optimizer.Gui.Core.Tests
{
    public class DecisionsViewTests
    {
        private static DecisionsView View(string line)
        {
            return DecisionsView.Build((ResultRecord)ScanRecordReader.Read(line));
        }

        private static DecisionsView Golden()
        {
            return View(Fixture.GoldenResult());
        }

        [Fact]
        public void The_queue_holds_one_card_per_row_in_the_engines_own_order()
        {
            DecisionsView view = Golden();

            // Five rows across four sections: the Installed apps section holds
            // two, one from the curated list and one from a usage signal, which
            // is the shape that section really has.
            Assert.Equal(5, view.Card.Count);
            Assert.Equal(
                new[] { "StartupItems", "InstalledApps", "InstalledApps", "JunkFiles", "Services" },
                view.Card.Select(c => c.SectionKey).ToArray());
        }

        [Fact]
        public void A_card_key_survives_two_rows_with_the_same_display_name()
        {
            // Display names really do collide -- the engine splices a FindingId
            // column into a whole section because of it -- so the key is the
            // section and the row number, not the name.
            DecisionsView view = Golden();

            Assert.Equal(view.Card.Count, view.Card.Select(c => c.Key).Distinct().Count());
            Assert.Equal("StartupItems#1", view.Card[0].Key);
        }

        [Fact]
        public void The_safety_label_is_carried_verbatim_and_the_stripe_fails_closed()
        {
            DecisionsView view = Golden();

            // The curated-list row: Confidence 'Known' and no consent required,
            // which is the only combination the rule calls safe. The unused-app
            // row beside it is Heuristic, so the same section carries both
            // labels and this is not a test about one tame row.
            DecisionCard safe = view.Card.First(c => c.SectionKey == "InstalledApps");
            Assert.Equal(ScanContract.SafetyLabelSafe, safe.SafetyLabel);
            Assert.True(safe.IsSafe);

            DecisionCard heuristic = view.Card.Last(c => c.SectionKey == "InstalledApps");
            Assert.Equal(ScanContract.SafetyLabelReview, heuristic.SafetyLabel);
            Assert.False(heuristic.IsSafe);

            DecisionCard review = view.Card.Single(c => c.SectionKey == "StartupItems");
            Assert.Equal(ScanContract.SafetyLabelReview, review.SafetyLabel);
            Assert.False(review.IsSafe);
        }

        [Fact]
        public void A_safety_label_this_shell_has_never_seen_is_presented_as_needing_review()
        {
            // Get-ReviewSafetyStyle maps the one safe string to the safe style
            // and everything else to review. Kept identical here, so a label
            // added later is never shown as safe by default.
            string line = Fixture.GoldenResult().Replace(
                "\"SafetyLabel\":\"Safe to remove\"", "\"SafetyLabel\":\"Probably fine\"");

            DecisionCard card = View(line).Card.First(c => c.SectionKey == "InstalledApps");

            Assert.Equal("Probably fine", card.SafetyLabel);
            Assert.False(card.IsSafe);
        }

        [Fact]
        public void The_reason_comes_from_the_why_flagged_column_where_the_section_has_one()
        {
            DecisionsView view = Golden();

            Assert.Equal("Target file is missing", view.Card.Single(c => c.SectionKey == "StartupItems").LeadLine);
            Assert.Equal("List entry 'fixture-widget'", view.Card.First(c => c.SectionKey == "InstalledApps").LeadLine);
            Assert.Equal("On the curated list", view.Card.Single(c => c.SectionKey == "Services").LeadLine);
        }

        [Fact]
        public void The_junk_card_reads_its_reason_off_the_evidence_because_it_has_no_reason_column()
        {
            // The junk section's rows are sized, not argued: its columns are
            // Location, On disk now, Files, Older than and Safety. The reason
            // is what the detector wrote as evidence.
            DecisionCard junk = Golden().Card.Single(c => c.SectionKey == "JunkFiles");

            Assert.Equal("Fixture web cache -- 1,234 files older than 7 days.", junk.LeadLine);
            Assert.Equal(junk.Evidence[0], junk.LeadLine);
        }

        [Fact]
        public void The_card_detail_is_the_remaining_cells_under_their_own_headings()
        {
            DecisionCard junk = Golden().Card.Single(c => c.SectionKey == "JunkFiles");

            Assert.Equal(
                new[] { "On disk now", "Files", "Older than" },
                junk.Detail.Select(d => d.Label).ToArray());

            // Verbatim, including the engine's own "or more" for a size that is
            // a floor rather than a total.
            Assert.Equal("1.14 GiB or more", junk.Detail[0].Value);
            Assert.Equal("1,234", junk.Detail[1].Value);
            Assert.Equal("30 days", junk.Detail[2].Value);
        }

        [Fact]
        public void The_number_the_name_and_the_safety_label_are_not_repeated_in_the_detail()
        {
            foreach (DecisionCard card in Golden().Card)
            {
                Assert.DoesNotContain(card.Detail, d => d.Label == "#");
                Assert.DoesNotContain(card.Detail, d => d.Label == "Safety");
                Assert.DoesNotContain(card.Detail, d => d.Value == card.Title);
                Assert.DoesNotContain(card.Detail, d => d.Label == "Why flagged");
            }
        }

        [Fact]
        public void The_preview_text_reaches_the_card_unchanged()
        {
            DecisionCard card = Golden().Card.Single(c => c.SectionKey == "StartupItems");

            Assert.True(card.HasPlan);
            Assert.Equal(2, card.PreviewText.Count);
            Assert.Equal(@"Plan for HKCU\Run\Fixture", card.PreviewText[0]);
            Assert.Equal(
                "  This is what would happen. It is not a promise about what this PC will do afterwards.",
                card.PreviewText[1]);
        }

        [Fact]
        public void The_inventory_strip_carries_each_sections_own_headline_verbatim()
        {
            DecisionsView view = Golden();

            Assert.Equal(4, view.Strip.Count);

            SectionStrip apps = view.Strip.Single(i => i.SectionKey == "InstalledApps");

            // The sentence the whole screen is built around, and it is the
            // engine's, not this shell's.
            Assert.Equal("Could not judge 2 of 5 installed applications.", apps.Lead);
            Assert.Equal(
                "1 were used recently, 2 look unused, 1 are on the exclusion list and were never considered.",
                apps.Detail[0]);
            Assert.Equal(2, apps.DecisionCount);
        }

        [Fact]
        public void A_section_with_no_rows_carries_the_engines_own_empty_text()
        {
            string line = Fixture.GoldenResult().Replace(
                "\"EmptyText\":\"No service is flagged.\",\"RowCount\":1,\"Row\":[{\"Number\":1,\"SectionKey\":\"Services\"",
                "\"EmptyText\":\"No service is flagged.\",\"RowCount\":0,\"Row\":[],\"Unused\":[{\"Number\":1,\"SectionKey\":\"Services\"");

            SectionStrip services = View(line).Strip.Single(i => i.SectionKey == "Services");

            Assert.Equal(0, services.DecisionCount);

            // Never "nothing found": each section says what an empty list does
            // and does not prove.
            Assert.Equal("No service is flagged.", services.EmptyText);
        }

        [Fact]
        public void A_section_with_rows_has_no_empty_text_to_show()
        {
            Assert.All(Golden().Strip, i => Assert.Null(i.EmptyText));
        }

        [Fact]
        public void Skipped_and_failed_sources_reach_the_screen_with_their_reasons()
        {
            DecisionsView view = Golden();

            Assert.Equal(3, view.Incomplete.Count);

            SourceNote failed = view.Incomplete.Single(s => s.Status == ScanContract.StatusFailed);
            Assert.Equal("ScheduledTask", failed.Name);
            Assert.Equal("The task scheduler service could not be reached.", failed.Reason);

            Assert.All(view.Incomplete, s => Assert.False(string.IsNullOrEmpty(s.Reason)));
        }

        [Fact]
        public void A_refused_source_is_kept_apart_from_the_incomplete_ones()
        {
            DecisionsView view = Golden();

            Assert.DoesNotContain(view.Incomplete, s => s.Status == ScanContract.StatusRefused);

            SourceNote refused = Assert.Single(view.Refused);
            Assert.Equal("FileSystemLastAccess", refused.Name);

            // Reporting a deliberate refusal as a failure would be wrong in the
            // direction that flatters the tool.
            Assert.Equal(ScanContract.StatusRefused, refused.Status);
        }

        [Fact]
        public void The_partial_sections_are_named_on_the_screen()
        {
            DecisionsView view = Golden();

            Assert.False(view.IsComplete);
            Assert.Equal(4, view.PartialSection.Count);
            Assert.Contains("Installed apps", view.PartialSection);
        }

        [Fact]
        public void A_row_whose_plan_is_unsupported_is_held_back_with_the_engines_reason()
        {
            string line = Fixture.GoldenResult().Replace(
                "\"Route\":\"FixtureRoute\",\"Supported\":true,\"UnsupportedReason\":null",
                "\"Route\":\"Unsupported\",\"Supported\":false,\"UnsupportedReason\":\"No route carries out this removal method.\"");

            DecisionsView view = View(line);

            Assert.All(view.Card, c => Assert.False(c.IsSelectable));
            Assert.All(view.Card, c =>
                Assert.Equal("No route carries out this removal method.", c.HeldBackReason));
        }

        [Fact]
        public void With_no_plans_nothing_is_held_back_and_the_screen_says_so()
        {
            string line = System.Text.RegularExpressions.Regex.Replace(
                Fixture.GoldenResult(), ",\"Plan\":\\{[^}]*\\}\\}", "}");

            DecisionsView view = View(line);

            Assert.True(view.PlansWereSkipped);
            Assert.All(view.Card, c => Assert.False(c.HasPlan));
            Assert.All(view.Card, c => Assert.Empty(c.PreviewText));

            // Nothing is held back, because there is no Supported to read --
            // and that is stated rather than left to read as permission.
            Assert.All(view.Card, c => Assert.True(c.IsSelectable));
            Assert.All(view.Card, c => Assert.Null(c.HeldBackReason));
        }

        [Fact]
        public void An_empty_scan_does_not_claim_plans_were_skipped()
        {
            // With no rows there is nothing to conclude either way, and saying
            // plans were skipped would be an invention.
            DecisionsView view = View(Fixture.EmptyResult());

            Assert.Empty(view.Card);
            Assert.False(view.PlansWereSkipped);
        }
    }
}
