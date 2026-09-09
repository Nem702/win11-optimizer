using System.Collections.Generic;
using System.Linq;
using Win11Optimizer.Gui.Core;
using Win11Optimizer.Gui.Core.Contract;
using Win11Optimizer.Gui.Core.Json;
using Xunit;

namespace Win11Optimizer.Gui.Core.Tests
{
    /// <summary>
    /// Inventory[], read off the committed bytes. Chunk P6-C3.
    /// </summary>
    /// <remarks>
    /// <para>
    /// THESE BIND. THEY DO NOT DRAW. No category table exists yet and none is
    /// in this chunk; the point of binding first is that the next chunk starts
    /// from a binder whose failure mode is a red test on the same commit as the
    /// PowerShell, rather than a wrong table in the field.
    /// </para>
    /// <para>
    /// Every one of them reads tests\Fixtures\json-contract-golden.jsonl rather
    /// than a copy of it, for the reason the rest of the suite does: if the
    /// engine's projection changes shape, the file changes and these fail.
    /// </para>
    /// </remarks>
    public class InventoryContractTests
    {
        private static ResultRecord Result()
        {
            return (ResultRecord)ScanRecordReader.Read(Fixture.GoldenResult());
        }

        private static SectionRecord Section(string key)
        {
            return Result().Section.Single(s => s.Key == key);
        }

        [Fact]
        public void Every_section_carries_an_inventory_and_a_count_that_agrees_with_it()
        {
            foreach (SectionRecord section in Result().Section)
            {
                Assert.NotEmpty(section.Inventory);
                Assert.Equal(section.InventoryCount, section.Inventory.Count);
            }
        }

        [Fact]
        public void The_inventory_is_what_the_section_looked_at_and_the_rows_are_only_what_it_flagged()
        {
            // The whole reason this field exists. Every section inspected more
            // than it flagged, and before P6-C3 the difference existed only
            // inside the headline sentences.
            foreach (SectionRecord section in Result().Section)
            {
                Assert.True(
                    section.Inventory.Count > section.Row.Count,
                    "Section '" + section.Key + "' inspected " + section.Inventory.Count +
                    " objects and flagged " + section.Row.Count + ".");
            }
        }

        [Fact]
        public void Every_entry_carries_one_of_the_three_published_classes()
        {
            foreach (SectionRecord section in Result().Section)
            {
                foreach (InventoryRecord entry in section.Inventory)
                {
                    Assert.Contains(entry.Class, (string[])ScanContract.InventoryClasses);
                    Assert.False(string.IsNullOrEmpty(entry.Id));
                    Assert.False(string.IsNullOrEmpty(entry.DisplayName));
                    Assert.False(string.IsNullOrEmpty(entry.Category));
                }
            }
        }

        [Fact]
        public void A_fourth_inventory_class_is_refused_rather_than_filed_under_the_nearest_one()
        {
            // The same refusal, and the same reason, as an unrecognised source
            // status: a held-back object shown as one nothing was said about is
            // the under-report this project exists to prevent, and guessing is
            // how a consumer arrives at it.
            string line = Fixture.GoldenResult().Replace(
                "\"Class\":\"HeldBack\"", "\"Class\":\"Exempted\"");

            var ex = Assert.Throws<ScanProtocolException>(() => ScanRecordReader.Read(line));

            Assert.Contains("Exempted", ex.Message);
            Assert.Contains("HeldBack", ex.Message);
        }

        [Fact]
        public void A_count_that_disagrees_with_the_list_is_refused()
        {
            // Both are written from one array by one projection, so they cannot
            // legitimately differ. A table drawn from half an inventory reports
            // less than the truth and raises nothing, which is exactly the shape
            // of failure this codebase treats as the serious kind.
            string line = Fixture.GoldenResult().Replace(
                "\"InventoryCount\":7,", "\"InventoryCount\":9,");

            var ex = Assert.Throws<ScanProtocolException>(() => ScanRecordReader.Read(line));

            Assert.Contains("StartupItems", ex.Message);
            Assert.Contains("cannot disagree", ex.Message);
        }

        [Fact]
        public void The_startup_section_holds_every_mechanism_including_the_services()
        {
            // "7 things start with your PC" counts the services among them, so
            // the list that sentence is about has to as well.
            SectionRecord startup = Section(ScanContract.SectionStartupItems);

            Assert.Equal(7, startup.Inventory.Count);
            Assert.Equal(
                new[] { "RunKey", "StartupFolder", "ScheduledTask", "Service" },
                startup.Inventory.Select(i => i.Mechanism).Distinct().OrderBy(m => m == "RunKey" ? 0 : m == "StartupFolder" ? 1 : m == "ScheduledTask" ? 2 : 3).ToArray());

            // Category is the object's, not the section's: a service that starts
            // with the PC is a Service inside the StartupItems section.
            Assert.Equal(2, startup.Inventory.Count(i => i.Category == "Service"));
        }

        [Fact]
        public void The_held_back_count_matches_the_engines_own_protected_counts()
        {
            // THE ASSERTION THIS CHUNK EXISTS FOR. The headline sentences quote
            // ProtectedTaskCount and ProtectedServiceCount; until now those were
            // numbers in prose and nothing could check them against a list.
            SectionRecord startup = Section(ScanContract.SectionStartupItems);

            Assert.Equal(1, startup.Inventory.Count(i => i.IsHeldBack && i.Category == "StartupItem"));
            Assert.Equal(1, startup.Inventory.Count(i => i.IsHeldBack && i.Category == "Service"));

            SectionRecord services = Section(ScanContract.SectionServices);
            Assert.Equal(1, services.Inventory.Count(i => i.IsHeldBack));
        }

        [Fact]
        public void A_held_back_object_names_the_curated_entry_that_held_it_back()
        {
            InventoryRecord held = Section(ScanContract.SectionServices)
                .Inventory.Single(i => i.IsHeldBack);

            Assert.Equal("FixtureProtectedSvc", held.Id);

            // Structured, so a view reads the class rather than string-matching
            // the reason prose.
            Assert.True(held.HasRuleId);
            Assert.Equal("fixture-security-class", held.RuleId);
            Assert.True(held.HasRuleClass);
            Assert.Equal("security", held.RuleClass);

            // And the curated entry's own worded reason, copied not composed.
            Assert.True(held.HasReason);
            Assert.Equal(
                "Security software is never offered, whatever a usage heuristic says about it.",
                held.Reason);

            // It was held back, so nothing flagged it and there is no row to
            // point at. Absent, not null.
            Assert.False(held.HasFindingId);
        }

        [Fact]
        public void An_object_nothing_was_flagged_about_carries_no_reason_and_no_rule()
        {
            InventoryRecord quiet = Section(ScanContract.SectionStartupItems)
                .Inventory.Single(i => i.Id == @"HKCU\Run\Quiet");

            Assert.Equal(ScanContract.InventoryNotFlagged, quiet.Class);

            // ABSENT, NOT NULL. A row nothing flagged has nothing to say, and a
            // null there would be a placeholder for something that does not
            // exist.
            Assert.False(quiet.HasReason);
            Assert.False(quiet.HasRuleId);
            Assert.False(quiet.HasRuleClass);
            Assert.False(quiet.HasFindingId);
        }

        [Fact]
        public void A_flagged_object_names_its_row_and_the_name_is_not_always_its_own_id()
        {
            SectionRecord apps = Section(ScanContract.SectionInstalledApps);

            // The Appx case, and the reason FindingId is carried rather than
            // guessed at: Find-UnusedApp keys the Finding on the package family
            // name while the inventory keys on the app's own Id.
            InventoryRecord unused = apps.Inventory.Single(
                i => i.Id == "Fixture.Unused_1.0.0.0_x64__8wekyb3d8bbwe");

            Assert.True(unused.IsFlagged);
            Assert.True(unused.HasFindingId);
            Assert.Equal("Fixture.Unused_8wekyb3d8bbwe", unused.FindingId);
            Assert.NotEqual(unused.Id, unused.FindingId);

            // And it really does name a row in this section.
            Assert.Contains(apps.Row, r => r.FindingId == unused.FindingId);
        }

        [Fact]
        public void Every_flagged_entry_names_a_row_somewhere_in_the_payload()
        {
            ResultRecord result = Result();

            var findingIds = new HashSet<string>(
                result.Section.SelectMany(s => s.Row).Select(r => r.FindingId));

            foreach (SectionRecord section in result.Section)
            {
                foreach (InventoryRecord entry in section.Inventory.Where(i => i.IsFlagged))
                {
                    Assert.True(entry.HasFindingId,
                        "Flagged entry '" + entry.Id + "' does not say which finding it became.");
                    Assert.Contains(entry.FindingId, findingIds);
                }
            }
        }

        [Fact]
        public void The_two_tri_states_arrive_present_and_null_rather_than_false()
        {
            // TargetExists and Exists are the only nullable booleans in the
            // inventory, and null on either means "could not be determined".
            // Only false is "proved absent" -- collapsing the two would
            // manufacture an orphan out of a permission the scan did not have.
            InventoryRecord murky = Section(ScanContract.SectionStartupItems)
                .Inventory.Single(i => i.Id == @"C:\Fixture\Startup\murky.lnk");

            Assert.True(murky.HasTargetExists);
            Assert.Null(murky.TargetExists);

            InventoryRecord orphan = Section(ScanContract.SectionStartupItems)
                .Inventory.Single(i => i.Id == @"HKCU\Run\Fixture");

            Assert.True(orphan.HasTargetExists);
            Assert.False(orphan.TargetExists);

            InventoryRecord temp = Section(ScanContract.SectionJunkFiles)
                .Inventory.Single(i => i.Id == "windows-temp");

            Assert.True(temp.HasExists);
            Assert.Null(temp.Exists);
        }

        [Fact]
        public void A_category_carries_only_its_own_fields()
        {
            // Bound by key presence, not by category -- the same rule the row
            // binder keeps, and for the same reason: the engine owns the table
            // saying which category has which field, and a second copy here is
            // somewhere for the two to disagree.
            InventoryRecord startup = Section(ScanContract.SectionStartupItems)
                .Inventory.First();

            Assert.True(startup.HasMechanism);
            Assert.True(startup.HasScope);
            Assert.True(startup.HasEnabledState);
            Assert.True(startup.HasTargetExists);
            Assert.False(startup.HasStatus);
            Assert.False(startup.HasEligibleBytes);
            Assert.False(startup.HasState);

            InventoryRecord app = Section(ScanContract.SectionInstalledApps).Inventory.First();
            Assert.True(app.HasSource);
            Assert.True(app.HasDetail);
            Assert.True(app.HasState);
            Assert.False(app.HasMechanism);
            Assert.False(app.HasExists);

            InventoryRecord junk = Section(ScanContract.SectionJunkFiles).Inventory.First();
            Assert.True(junk.HasStatus);
            Assert.True(junk.HasIsAssessed);
            Assert.True(junk.HasFileCount);
            Assert.True(junk.HasEligibleBytes);
            Assert.True(junk.HasIsSizeFloor);
            Assert.True(junk.HasMinimumAgeDays);
            Assert.False(junk.HasMechanism);
            Assert.False(junk.HasPublisher);
        }

        [Fact]
        public void The_junk_inventory_reports_the_locations_that_produced_nothing()
        {
            // New-JunkLocation's own rule, now across the boundary: every
            // curated location is reported, including the ones that were never
            // offered and the ones that could not be read. "Recycle Bin"
            // silently absent is the failure this project is built against.
            SectionRecord junk = Section(ScanContract.SectionJunkFiles);

            Assert.Equal(3, junk.Inventory.Count);
            Assert.Single(junk.Row);

            InventoryRecord held = junk.Inventory.Single(i => i.IsHeldBack);
            Assert.Equal("fixture-prefetch", held.Id);
            Assert.True(held.HasReason);

            // Measured and never offered: the size is real, the eligible count
            // is zero, and both are on the record.
            Assert.Equal(244, held.FileCount);
            Assert.Equal(0, held.EligibleFileCount);
        }

        [Fact]
        public void A_used_application_carries_the_classifiers_own_sentence()
        {
            InventoryRecord used = Section(ScanContract.SectionInstalledApps)
                .Inventory.Single(i => i.Id == @"HKLM\Fixture\Uninstall\Used");

            Assert.Equal(ScanContract.InventoryNotFlagged, used.Class);
            Assert.Equal("Used", used.State);

            // Copied, never composed from the scalars beside it.
            Assert.True(used.HasReason);
            Assert.Equal("Launched 4 days ago, inside the 180-day window.", used.Reason);
        }

        [Fact]
        public void Nothing_rule_shaped_or_file_shaped_rides_along_with_the_inventory()
        {
            // The same guard the row projection has. An inventory of 289 records
            // is the largest thing in this payload and the easiest place for a
            // whole object to arrive by accident.
            foreach (string line in Fixture.GoldenLines())
            {
                Assert.DoesNotContain("InventoryVerdict", line);
                Assert.DoesNotContain("\"App\":", line);
                Assert.DoesNotContain("ResolvedPath", line);
                Assert.DoesNotContain("DeclaredPath", line);
                Assert.DoesNotContain("MatchedSignals", line);
                Assert.DoesNotContain("SignalDetail", line);
            }
        }
    }
}
