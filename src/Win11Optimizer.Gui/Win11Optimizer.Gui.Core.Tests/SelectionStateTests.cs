using System.Linq;
using Win11Optimizer.Gui.Core.Contract;
using Win11Optimizer.Gui.Core.Json;
using Win11Optimizer.Gui.Core.View;
using Xunit;

namespace Win11Optimizer.Gui.Core.Tests
{
    public class SelectionStateTests
    {
        private static DecisionsView Golden()
        {
            return DecisionsView.Build((ResultRecord)ScanRecordReader.Read(Fixture.GoldenResult()));
        }

        [Fact]
        public void Nothing_is_selected_to_begin_with()
        {
            Assert.Equal(0, new SelectionState().Count);
        }

        [Fact]
        public void Toggling_selects_and_deselects()
        {
            DecisionsView view = Golden();
            var selection = new SelectionState();
            DecisionCard card = view.Card[0];

            Assert.True(selection.Toggle(card));
            Assert.True(selection.IsSelected(card.Key));
            Assert.Equal(1, selection.Count);

            Assert.False(selection.Toggle(card));
            Assert.False(selection.IsSelected(card.Key));
            Assert.Equal(0, selection.Count);
        }

        [Fact]
        public void Selecting_a_section_takes_only_that_sections_cards()
        {
            DecisionsView view = Golden();
            var selection = new SelectionState();

            int added = selection.SelectSection(view.Card, "JunkFiles");

            Assert.Equal(1, added);
            Assert.Equal(1, selection.Count);
            Assert.All(selection.Selected(view.Card), c => Assert.Equal("JunkFiles", c.SectionKey));
        }

        [Fact]
        public void Selecting_the_same_section_twice_adds_nothing_the_second_time()
        {
            DecisionsView view = Golden();
            var selection = new SelectionState();

            selection.SelectSection(view.Card, "JunkFiles");
            Assert.Equal(0, selection.SelectSection(view.Card, "JunkFiles"));
            Assert.Equal(1, selection.Count);
        }

        [Fact]
        public void Clearing_empties_the_selection()
        {
            DecisionsView view = Golden();
            var selection = new SelectionState();

            foreach (DecisionCard card in view.Card)
            {
                selection.Select(card);
            }

            Assert.Equal(5, selection.Count);
            selection.Clear();
            Assert.Equal(0, selection.Count);
        }

        [Fact]
        public void The_selected_list_is_in_queue_order_not_in_the_order_they_were_ticked()
        {
            DecisionsView view = Golden();
            var selection = new SelectionState();

            selection.Select(view.Card[3]);
            selection.Select(view.Card[1]);
            selection.Select(view.Card[0]);

            Assert.Equal(
                new[] { view.Card[0].Key, view.Card[1].Key, view.Card[3].Key },
                selection.Selected(view.Card).Select(c => c.Key).ToArray());
        }

        [Fact]
        public void A_card_the_engine_held_back_cannot_be_selected()
        {
            string line = Fixture.GoldenResult().Replace(
                "\"Route\":\"FixtureRoute\",\"Supported\":true,\"UnsupportedReason\":null",
                "\"Route\":\"Unsupported\",\"Supported\":false,\"UnsupportedReason\":\"No route carries this out.\"");

            DecisionsView view = DecisionsView.Build((ResultRecord)ScanRecordReader.Read(line));
            var selection = new SelectionState();

            DecisionCard card = view.Card[0];

            // Refused rather than silently ignored: a caller that believed
            // something was selected would be worse off than one told it was
            // not.
            Assert.False(selection.Select(card));
            Assert.False(selection.Toggle(card));
            Assert.Equal(0, selection.Count);
        }

        [Fact]
        public void Selecting_never_changes_the_parsed_result()
        {
            DecisionsView view = Golden();
            var selection = new SelectionState();

            string beforeLabel = view.Card[0].SafetyLabel;
            bool beforeSelectable = view.Card[0].IsSelectable;
            int beforeCount = view.Card.Count;

            foreach (DecisionCard card in view.Card)
            {
                selection.Toggle(card);
            }

            Assert.Equal(beforeLabel, view.Card[0].SafetyLabel);
            Assert.Equal(beforeSelectable, view.Card[0].IsSelectable);
            Assert.Equal(beforeCount, view.Card.Count);
        }

        [Fact]
        public void A_selection_of_something_no_longer_on_screen_is_dropped()
        {
            DecisionsView view = Golden();
            var selection = new SelectionState();

            foreach (DecisionCard card in view.Card)
            {
                selection.Select(card);
            }

            DecisionsView smaller =
                DecisionsView.Build((ResultRecord)ScanRecordReader.Read(Fixture.EmptyResult()));

            selection.Retain(smaller.Card);

            Assert.Equal(0, selection.Count);
        }
    }
}
