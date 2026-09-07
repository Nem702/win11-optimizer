using System;
using System.Collections.Generic;
using Win11Optimizer.Gui.Core.Contract;

namespace Win11Optimizer.Gui.Core.View
{
    public enum ScanPhaseState
    {
        Pending,
        Running,
        Done
    }

    public sealed class ScanPhaseView
    {
        internal ScanPhaseView() { }

        /// <summary>The contract's own phase name.</summary>
        public string Key { get; internal set; }

        /// <summary>
        /// The engine's sentence for this phase once it has said one, and the
        /// phase key until then.
        /// </summary>
        /// <remarks>
        /// THIS SHELL DOES NOT CARRY A TABLE OF PHASE DISPLAY NAMES, and the
        /// omission is deliberate. The engine already writes a sentence for
        /// every phase ("Reading what starts with this PC."), and a second copy
        /// of those words here would be the re-wording the brief forbids --
        /// with the added property that the two copies could drift. So a phase
        /// that has not started yet shows its key. In practice that is brief:
        /// the progress line for a phase is written BEFORE its work begins, so
        /// the sentence arrives as the phase does.
        /// </remarks>
        public string Label { get; internal set; }

        public ScanPhaseState State { get; internal set; }
    }

    /// <summary>
    /// The scanning screen, driven from the progress lines.
    /// </summary>
    /// <remarks>
    /// A run that has stopped must never look like a run that is working, which
    /// is why the junk phase names the location it is on: it is the longest
    /// phase in the tool and the only one whose work is a list a person can
    /// watch go by.
    /// </remarks>
    public sealed class ScanningView
    {
        private readonly Dictionary<string, string> _labelSeen =
            new Dictionary<string, string>(StringComparer.Ordinal);

        private string _currentPhase;

        public ScanningView()
        {
            PhaseCount = ScanContract.Phases.Count;
            Rebuild();
        }

        public IReadOnlyList<ScanPhaseView> Phase { get; private set; }

        /// <summary>The engine's own sentence for what is happening now.</summary>
        public string Message { get; private set; }

        /// <summary>What it is on now, or null when this phase is not a list.</summary>
        public string Item { get; private set; }

        public long ItemIndex { get; private set; }
        public long ItemCount { get; private set; }
        public long PhaseIndex { get; private set; }
        public long PhaseCount { get; private set; }

        /// <summary>
        /// How many findings the scan has SO FAR. It is not a total: the phases
        /// that would make it one have not finished. Named so that nothing can
        /// render it as one by accident.
        /// </summary>
        public long FindingCountSoFar { get; private set; }

        /// <summary>How many objects have been inventoried SO FAR. Also not a total.</summary>
        public long InventoryCountSoFar { get; private set; }

        /// <summary>
        /// Rough progress, 0 to 1, from the phase position and the item
        /// position within it. Arithmetic over numbers the engine published; it
        /// is not an estimate of time and nothing presents it as one.
        /// </summary>
        public double Fraction { get; private set; }

        public void Apply(ProgressRecord progress)
        {
            if (progress == null)
            {
                throw new ArgumentNullException("progress");
            }

            _currentPhase = progress.Phase;
            Message = progress.Message;
            Item = progress.Item;
            ItemIndex = progress.ItemIndex;
            ItemCount = progress.ItemCount;
            PhaseIndex = progress.PhaseIndex;
            PhaseCount = progress.PhaseCount > 0 ? progress.PhaseCount : ScanContract.Phases.Count;
            FindingCountSoFar = progress.FindingCount;
            InventoryCountSoFar = progress.InventoryCount;

            if (!string.IsNullOrEmpty(progress.Phase) && !string.IsNullOrEmpty(progress.Message))
            {
                _labelSeen[progress.Phase] = progress.Message;
            }

            double within = 0.0;
            if (progress.ItemCount > 0 && progress.ItemIndex > 0)
            {
                within = Math.Min(1.0, (double)progress.ItemIndex / progress.ItemCount);
            }

            double phases = PhaseCount > 0 ? PhaseCount : 1;
            double done = Math.Max(0, progress.PhaseIndex - 1) + within;
            Fraction = Math.Max(0.0, Math.Min(1.0, done / phases));

            Rebuild();
        }

        private void Rebuild()
        {
            IList<string> phases = ScanContract.Phases;
            int current = _currentPhase == null ? -1 : ScanContract.PhaseIndexOf(_currentPhase) - 1;

            var views = new List<ScanPhaseView>(phases.Count);
            for (int i = 0; i < phases.Count; i++)
            {
                string key = phases[i];
                string label;
                if (!_labelSeen.TryGetValue(key, out label))
                {
                    label = key;
                }

                ScanPhaseState state;
                if (current < 0 || i > current)
                {
                    state = ScanPhaseState.Pending;
                }
                else if (i == current)
                {
                    state = ScanPhaseState.Running;
                }
                else
                {
                    state = ScanPhaseState.Done;
                }

                views.Add(new ScanPhaseView { Key = key, Label = label, State = state });
            }

            Phase = views;
        }
    }
}
