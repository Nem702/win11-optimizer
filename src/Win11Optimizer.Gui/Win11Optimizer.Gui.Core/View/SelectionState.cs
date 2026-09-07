using System;
using System.Collections.Generic;

namespace Win11Optimizer.Gui.Core.View
{
    /// <summary>
    /// What is ticked.
    /// </summary>
    /// <remarks>
    /// <para>
    /// IT GOES NOWHERE. This chunk is read-only: nothing takes a selection back
    /// into the engine, and there is no code path from here to anything that
    /// changes this PC. The type exists so that the screen can hold a
    /// selection, and so that the rule about what may be selected is written
    /// down somewhere a test can reach.
    /// </para>
    /// <para>
    /// THE RULE IS THE ENGINE'S, NOT THIS SHELL'S. A card is selectable when
    /// the engine's plan for it says Supported. Where the scan ran without
    /// planning there is no Supported to read, so nothing is held back and the
    /// screen says as much -- rather than letting the absence of a refusal read
    /// as permission.
    /// </para>
    /// </remarks>
    public sealed class SelectionState
    {
        private readonly HashSet<string> _selected = new HashSet<string>(StringComparer.Ordinal);

        public int Count
        {
            get { return _selected.Count; }
        }

        public bool IsSelected(string key)
        {
            return key != null && _selected.Contains(key);
        }

        /// <summary>
        /// Selects a card, or does nothing and returns false when the engine
        /// held it back. Silently ignoring the attempt would be worse than
        /// refusing it: the caller would believe something was selected.
        /// </summary>
        public bool Select(DecisionCard card)
        {
            if (card == null)
            {
                throw new ArgumentNullException("card");
            }

            if (!card.IsSelectable)
            {
                return false;
            }

            _selected.Add(card.Key);
            return true;
        }

        public void Deselect(DecisionCard card)
        {
            if (card == null)
            {
                throw new ArgumentNullException("card");
            }

            _selected.Remove(card.Key);
        }

        /// <summary>Returns whether the card is selected afterwards.</summary>
        public bool Toggle(DecisionCard card)
        {
            if (card == null)
            {
                throw new ArgumentNullException("card");
            }

            if (IsSelected(card.Key))
            {
                Deselect(card);
                return false;
            }

            return Select(card);
        }

        public int SelectSection(IEnumerable<DecisionCard> cards, string sectionKey)
        {
            if (cards == null)
            {
                throw new ArgumentNullException("cards");
            }

            int added = 0;
            foreach (DecisionCard card in cards)
            {
                if (!string.Equals(card.SectionKey, sectionKey, StringComparison.Ordinal))
                {
                    continue;
                }

                if (!IsSelected(card.Key) && Select(card))
                {
                    added++;
                }
            }

            return added;
        }

        public void Clear()
        {
            _selected.Clear();
        }

        /// <summary>
        /// The selected cards, in the order the queue holds them rather than
        /// the order they were ticked in. A list whose order depended on the
        /// clicking would not match the screen it came from.
        /// </summary>
        public IReadOnlyList<DecisionCard> Selected(IEnumerable<DecisionCard> cards)
        {
            if (cards == null)
            {
                throw new ArgumentNullException("cards");
            }

            var result = new List<DecisionCard>();
            foreach (DecisionCard card in cards)
            {
                if (IsSelected(card.Key))
                {
                    result.Add(card);
                }
            }

            return result;
        }

        /// <summary>
        /// Drops selections whose cards are no longer on screen. A key that
        /// survived a re-scan into a queue that no longer holds it would be a
        /// selection of something invisible.
        /// </summary>
        public void Retain(IEnumerable<DecisionCard> cards)
        {
            if (cards == null)
            {
                throw new ArgumentNullException("cards");
            }

            var present = new HashSet<string>(StringComparer.Ordinal);
            foreach (DecisionCard card in cards)
            {
                present.Add(card.Key);
            }

            _selected.RemoveWhere(delegate (string key) { return !present.Contains(key); });
        }
    }
}
