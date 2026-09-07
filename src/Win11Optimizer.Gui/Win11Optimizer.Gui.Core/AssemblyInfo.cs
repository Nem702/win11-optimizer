using System.Runtime.CompilerServices;

// The tests construct contract records directly for the cases that are awkward
// to express as JSON. Everything they can reach through the binder, they reach
// through the binder -- a view-model test that parses real contract text is
// also a contract test.
[assembly: InternalsVisibleTo("Win11Optimizer.Gui.Core.Tests")]
