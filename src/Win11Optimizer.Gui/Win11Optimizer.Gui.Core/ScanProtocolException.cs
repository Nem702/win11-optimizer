using System;
using System.Runtime.Serialization;

namespace Win11Optimizer.Gui.Core
{
    /// <summary>
    /// The stream said something this shell will not render.
    /// </summary>
    /// <remarks>
    /// Every refusal in the data layer is one of these, and every one of them
    /// reaches the screen. Nothing in this shell may swallow one and carry on
    /// with a partly-bound record: a screen built from a payload that was only
    /// mostly understood is exactly the "returned less than the truth and
    /// raised nothing" failure docs\REVIEW.md catalogues.
    /// </remarks>
    [Serializable]
    public class ScanProtocolException : Exception
    {
        public ScanProtocolException() { }

        public ScanProtocolException(string message) : base(message) { }

        public ScanProtocolException(string message, Exception inner) : base(message, inner) { }

        protected ScanProtocolException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
    }
}
