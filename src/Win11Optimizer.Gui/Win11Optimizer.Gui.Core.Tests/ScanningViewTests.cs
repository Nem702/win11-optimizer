using System.Linq;
using Win11Optimizer.Gui.Core.Contract;
using Win11Optimizer.Gui.Core.Json;
using Win11Optimizer.Gui.Core.View;
using Xunit;

namespace Win11Optimizer.Gui.Core.Tests
{
    public class ScanningViewTests
    {
        private static ProgressRecord Read(string line)
        {
            return (ProgressRecord)ScanRecordReader.Read(line);
        }

        [Fact]
        public void All_five_phases_are_listed_before_anything_has_happened()
        {
            var view = new ScanningView();

            Assert.Equal(5, view.Phase.Count);
            Assert.Equal(ScanContract.Phases.ToArray(), view.Phase.Select(p => p.Key).ToArray());
            Assert.All(view.Phase, p => Assert.Equal(ScanPhaseState.Pending, p.State));
        }

        [Fact]
        public void A_phase_that_has_not_started_shows_its_key_rather_than_a_sentence_this_shell_invented()
        {
            var view = new ScanningView();

            Assert.All(view.Phase, p => Assert.Equal(p.Key, p.Label));
        }

        [Fact]
        public void A_phase_that_has_started_shows_the_engines_own_sentence()
        {
            var view = new ScanningView();
            view.Apply(Read(Fixture.GoldenProgress()));

            ScanPhaseView junk = view.Phase.Single(p => p.Key == ScanContract.PhaseJunkFiles);

            Assert.Equal("Measuring Fixture web cache.", junk.Label);
            Assert.Equal(ScanPhaseState.Running, junk.State);
        }

        [Fact]
        public void Earlier_phases_are_done_and_later_ones_are_pending()
        {
            var view = new ScanningView();
            view.Apply(Read(Fixture.GoldenProgress()));

            Assert.Equal(ScanPhaseState.Done, view.Phase[0].State);
            Assert.Equal(ScanPhaseState.Done, view.Phase[1].State);
            Assert.Equal(ScanPhaseState.Running, view.Phase[2].State);
            Assert.Equal(ScanPhaseState.Pending, view.Phase[3].State);
            Assert.Equal(ScanPhaseState.Pending, view.Phase[4].State);
        }

        [Fact]
        public void The_junk_phase_names_the_location_it_is_on()
        {
            // The longest phase in the tool, and the only one whose work is a
            // list a person can watch go by. A run that has stopped should
            // never look like a run that is working.
            var view = new ScanningView();
            view.Apply(Read(Fixture.GoldenProgress()));

            Assert.Equal("Fixture web cache", view.Item);
            Assert.Equal(9, view.ItemIndex);
            Assert.Equal(15, view.ItemCount);
        }

        [Fact]
        public void A_phase_with_no_item_list_reports_no_item_rather_than_a_blank_one()
        {
            var view = new ScanningView();
            view.Apply(Read(Fixture.Progress(ScanContract.PhaseStartupItems, 1)));

            // Null and empty are kept apart by the engine, so they are kept
            // apart here: "" would read as "there was an item and it was blank".
            Assert.Null(view.Item);
        }

        [Fact]
        public void The_counts_are_named_so_that_nothing_can_render_them_as_totals()
        {
            var view = new ScanningView();
            view.Apply(Read(Fixture.GoldenProgress()));

            Assert.Equal(3, view.FindingCountSoFar);
            Assert.Equal(778, view.InventoryCountSoFar);
        }

        [Fact]
        public void Progress_runs_from_zero_to_one_and_never_leaves_it()
        {
            var view = new ScanningView();

            view.Apply(Read(Fixture.Progress(ScanContract.PhaseStartupItems, 1)));
            Assert.Equal(0.0, view.Fraction);

            view.Apply(Read(Fixture.GoldenProgress()));
            Assert.InRange(view.Fraction, 0.4, 0.6);

            view.Apply(Read(Fixture.Progress(ScanContract.PhaseAssembling, 5)));
            Assert.InRange(view.Fraction, 0.0, 1.0);
        }

        [Fact]
        public void A_phase_label_once_seen_is_kept_when_the_scan_moves_on()
        {
            var view = new ScanningView();
            view.Apply(Read(Fixture.GoldenProgress()));
            view.Apply(Read(Fixture.Progress(ScanContract.PhaseAssembling, 5)));

            ScanPhaseView junk = view.Phase.Single(p => p.Key == ScanContract.PhaseJunkFiles);

            Assert.Equal("Measuring Fixture web cache.", junk.Label);
            Assert.Equal(ScanPhaseState.Done, junk.State);
        }
    }
}
