/*
    The painter.

    IT DECIDES NOTHING. Which cards exist, what order they are in, what a card's
    reason line is, what is held back and why -- all of that arrived already
    worked out from Win11Optimizer.Gui.Core, which is the half with tests. This
    file turns a view model into DOM and turns clicks back into messages. If
    something here starts branching on what a value MEANS rather than on whether
    it is there, it has crossed the line the testing split was drawn on.

    EVERY STRING FROM THE ENGINE IS SET WITH textContent, NEVER innerHTML. That
    is the injection guard, and it is also what makes "rendered verbatim" a
    property of the code rather than a promise: text that goes in through
    textContent comes out on screen as itself, markup and all.
*/

(function () {
  "use strict";

  // screen is what the host last said the run is doing. view is where in that
  // screen the rail has been pointed -- "decisions", or a section key.
  var state = { screen: "scanning", view: "decisions", data: null, selected: {}, count: 0 };

  // Section key -> the table the host sent, and -> the nodes a filter or a
  // sort has to touch. Both are emptied by the render that throws their DOM
  // away, for the reason cardNode is.
  var tableByKey = {};
  var tableNode = {};

  // Card key -> the nodes a selection change has to touch. Filled in as cards
  // are painted and emptied by the render that throws their DOM away, so it
  // never outlives the nodes it points at.
  //
  // A map held here rather than a lookup done later: finding a card again by
  // writing its Key into a DOM attribute would put an engine string into the
  // DOM as something other than text, and the rule at the top of this file is
  // that engine text reaches the DOM as text only.
  var cardNode = {};

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = text; }
    return node;
  }

  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  function send(message) {
    if (window.chrome && window.chrome.webview) {
      window.chrome.webview.postMessage(message);
    }
  }

  // ---- title bar ----------------------------------------------------------

  function paintTitleBar(d) {
    var meta = document.getElementById("meta");
    var tags = document.getElementById("tags");
    clear(tags);

    if (!d) { meta.textContent = ""; return; }

    var who = (d.machineName || "") + (d.userName ? "\\" + d.userName : "");
    meta.textContent = d.generatedUtc ? who + " " + d.generatedUtc : who;

    tags.appendChild(el("span", d.isElevated ? "tag warn" : "tag",
      d.isElevated ? "Administrator" : "Not administrator"));

    if (d.isComplete) {
      tags.appendChild(el("span", "tag good", "Complete - nothing skipped"));
    } else {
      // Named, never summarised. A tag saying "partial" without saying which
      // lists would be the under-report this tool exists to prevent, wearing a
      // warning.
      var names = (d.partialSection || []).join(", ");
      tags.appendChild(el("span", "tag warn",
        names ? "Partial - " + names : "Partial"));
    }
  }

  // ---- scanning -----------------------------------------------------------

  function paintScanning(d) {
    var col = el("div", "col");
    var box = el("div", "scan");

    box.appendChild(el("h2", "view", "Scanning"));
    box.appendChild(el("p", "sub",
      "Nothing is changed while this runs. Every phase names what it is doing, and the slow " +
      "one names the location it is on - a run that has stopped should never look like a run " +
      "that is working."));

    // Q30. A PHASE THAT HAS NOT STARTED SHOWS NO NAME AT ALL.
    //
    // The engine writes a human sentence for a phase in that phase's own first
    // progress line, so until then the only thing the shell holds is the
    // contract's machine key -- 'StartupItems', 'InstalledApps'. Those five keys
    // used to be painted on the first frame. A machine identifier reaching a
    // person is the bug; the fix is not to invent a second copy of the engine's
    // sentences in this file, which is what a phase-label table here would be
    // and what report 9.1 argued against. So a pending row is a dash, and the
    // engine's own words replace it the moment its progress line arrives.
    //
    // State is the authority, not a comparison of Label against Key: a pending
    // phase is exactly the one that has published no sentence yet, and once a
    // phase is running or done its label is the engine's.
    (d.phase || []).forEach(function (p) {
      var phaseState = p.State === 2 ? "done" : (p.State === 1 ? "now" : "");
      var row = el("div", "ph" + (phaseState ? " " + phaseState : " pending"));
      // A plain hyphen, not an em dash: every file in this project is ASCII and
      // one character above 0x7E in a source file is not a small problem here.
      row.appendChild(el("span", null, phaseState ? p.Label : "-"));
      row.appendChild(el("span", "t", phaseState === "done" ? "done" : ""));
      box.appendChild(row);
    });

    var bar = el("div", "bar");
    var fill = el("span");
    fill.style.width = Math.round((d.fraction || 0) * 100) + "%";
    bar.appendChild(fill);
    box.appendChild(bar);

    // The engine's sentence, then the position in the list it is working
    // through. The junk phase's message already names the location, so the name
    // is only added when the sentence does not already carry it - repeating it
    // is noise, and dropping it where it is absent would lose the one detail
    // that tells a stopped run from a working one.
    var current = d.message || "starting";
    if (d.item && current.indexOf(d.item) === -1) { current += "  " + d.item; }
    if (d.item && d.itemCount) {
      current += " (" + d.itemIndex + " of " + d.itemCount + ")";
    }
    box.appendChild(el("p", "cur", current));

    // "So far" is in the words, because these are not totals: the phases that
    // would make them totals have not finished.
    box.appendChild(el("p", "counts",
      d.inventoryCountSoFar + " objects looked at so far, " +
      d.findingCountSoFar + " flagged so far"));

    col.appendChild(box);
    return col;
  }

  // ---- the rail -----------------------------------------------------------

  // P6-C2 CUT THE RAIL RATHER THAN SHIP FOUR DEAD BUTTONS. It is back with the
  // screens it points at, and the one destination this build does not have is
  // drawn disabled with the reason on it -- which is the same call the
  // disabled "Review and apply" in the action bar is, and the opposite of what
  // the dropped rail would have been.
  function paintRail() {
    var rail = document.getElementById("rail");
    clear(rail);

    var d = state.data;
    if (!d || !d.rail) { return; }

    d.rail.forEach(function (r) {
      if (r.Key === "receipt") { rail.appendChild(el("div", "grp", "Records")); }

      var button = el("button", state.view === r.Key ? "on" : null);
      button.appendChild(el("span", null, r.Label));

      if (!r.IsBuilt) {
        button.appendChild(el("span", "todo", r.NotBuiltNote));
        button.disabled = true;
      } else if (r.IsQueue) {
        if (r.Count) { button.appendChild(el("span", "badge", String(r.Count))); }
        button.addEventListener("click", function () { go(r.Key); });
      } else {
        // THE SECTION'S OWN COUNT AND NOTHING ADDED TO IT. These four are never
        // summed anywhere: a service is in the startup section's inventory and
        // in the services section's, so the four added together counts the
        // services twice and is not the number of things inspected.
        button.appendChild(el("span", "ct", String(r.Count)));
        button.addEventListener("click", function () { go(r.Key); });
      }

      rail.appendChild(button);
    });
  }

  // Going somewhere else IS a new screen, so it renders whole and starts at the
  // top. That is the distinction the scroll rule turns on: a filter or a
  // selection changes the screen that is there, and navigation replaces it.
  function go(view) {
    state.view = view;
    render();
  }

  // ---- decisions ----------------------------------------------------------

  // WHAT "SELECTED" LOOKS LIKE, DECIDED IN ONE PLACE. Painting a card and
  // answering a selection change both come through here, so the class on the
  // card and the class and label on its button cannot drift apart. They were
  // written out twice before, and two copies is somewhere for them to
  // disagree.
  //
  // It reads whether the key is in state.selected and whether the engine
  // offered the row at all. It decides neither.
  function paintSelectedLook(entry) {
    if (!entry.selectable) {
      entry.card.className = entry.base;
      entry.pick.className = "btn";
      entry.pick.disabled = true;
      entry.pick.textContent = "Not offered";
      return;
    }

    var on = state.selected[entry.key] ? true : false;
    entry.card.className = entry.base + (on ? " pickd" : "");
    entry.pick.className = on ? "btn on" : "btn pri";
    entry.pick.disabled = false;
    entry.pick.textContent = on ? "Selected" : "Select";
  }

  function paintCard(c) {
    var node = el("div", "card" + (c.IsSafe ? " s-safe" : "") +
      (c.IsSelectable ? "" : " held"));

    node.appendChild(el("span", "stripe"));

    var body = el("div");

    var head = el("h3");
    head.appendChild(el("span", null, c.Title));
    head.appendChild(el("span", "pill " + (c.IsSafe ? "p-safe" : "p-rev"), c.SafetyLabel));
    if (c.HasPlan && c.IsReversible) { head.appendChild(el("span", "pill p-acc", "Reversible")); }
    if (!c.IsSelectable) { head.appendChild(el("span", "pill p-stop", "Held back")); }
    head.appendChild(el("span", "sect", c.SectionTitle));
    body.appendChild(head);

    if (c.LeadLine) { body.appendChild(el("p", null, c.LeadLine)); }

    if (c.Detail && c.Detail.length) {
      var kv = el("div", "kv");
      c.Detail.forEach(function (d) {
        var pair = el("span");
        pair.appendChild(el("b", null, d.Label + " "));
        pair.appendChild(document.createTextNode(d.Value));
        kv.appendChild(pair);
      });
      body.appendChild(kv);
    }

    if (c.Evidence && c.Evidence.length) {
      var ev = el("div", "ev");
      c.Evidence.forEach(function (line) {
        if (line !== c.LeadLine) { ev.appendChild(el("div", null, line)); }
      });
      if (ev.childNodes.length) { body.appendChild(ev); }
    }

    if (!c.IsSelectable && c.HeldBackReason) {
      body.appendChild(el("div", "note stop", c.HeldBackReason));
    }

    // The plan's own words, exactly as it wrote them, joined by the line breaks
    // it wrote them on. Nothing here shortens or rephrases them.
    //
    // COLLAPSED, because the plan preview is a later chunk. Rendering all of it
    // on every card would be that screen, built here by accident, and it buries
    // the queue: the plan for one Appx package is fifteen lines. Folded away it
    // stays one click from the card it belongs to, and it is still the plan's
    // own text when it opens - which is the only part of it this chunk is
    // making a promise about.
    if (c.PreviewText && c.PreviewText.length) {
      var fold = el("details", "pvwrap");
      fold.appendChild(el("summary", null, "What would happen to this"));
      fold.appendChild(el("div", "pv", c.PreviewText.join("\n")));
      body.appendChild(fold);
    }

    node.appendChild(body);

    var acts = el("div", "acts");
    var pick = el("button");
    if (c.IsSelectable) {
      pick.addEventListener("click", function () { send({ action: "toggle", key: c.Key }); });
    }
    acts.appendChild(pick);
    node.appendChild(acts);

    // The card's whole class list except the selected part, kept so that the
    // one function above can put it back without knowing how it was built.
    cardNode[c.Key] = {
      key: c.Key,
      card: node,
      pick: pick,
      base: node.className,
      selectable: c.IsSelectable ? true : false
    };
    paintSelectedLook(cardNode[c.Key]);

    return node;
  }

  function paintSectionStrip(i) {
    var row = el("div", "row");
    row.appendChild(el("span", "lead", i.Lead));
    row.appendChild(el("span", "n",
      i.DecisionCount === 1 ? "1 in the queue" : i.DecisionCount + " in the queue"));

    var why = el("span", "why");
    (i.Detail || []).forEach(function (line) { why.appendChild(el("div", null, line)); });
    if (i.EmptyText) { why.appendChild(el("div", null, i.EmptyText)); }
    if (!i.IsComplete && i.IncompleteReason) {
      why.appendChild(el("div", "part", i.IncompleteReason));
    }
    row.appendChild(why);

    // The strip says what a list looked at; this is how you see the list. It
    // goes to a screen that exists, which is the whole difference between it
    // and the four buttons P6-C2 took out.
    var all = el("button", "btn", "Show all");
    all.addEventListener("click", function () { go(i.SectionKey); });
    row.appendChild(all);

    return row;
  }

  function paintDecisions(d) {
    var col = el("div", "col");

    col.appendChild(el("h2", "view",
      (d.card.length === 1 ? "1 decision" : d.card.length + " decisions") +
      ", from " + d.strip.length + " lists"));
    col.appendChild(el("p", "sub",
      "Everything below was measured on this PC. Nothing has been changed, and nothing on " +
      "this screen is carried out - this build reads."));

    col.appendChild(el("p", "hd", "Needs a decision"));
    if (d.card.length) {
      var queue = el("div", "queue");
      d.card.forEach(function (c) { queue.appendChild(paintCard(c)); });
      col.appendChild(queue);
    } else {
      col.appendChild(el("div", "empty",
        "Nothing is flagged. What each list looked at, and what it could not judge, is below."));
    }

    // THE INVENTORY IS NOT A FOOTNOTE. Same weight as the cards, directly
    // under them.
    col.appendChild(el("p", "hd", "Inspected - nothing to decide"));
    var inv = el("div", "inv");
    d.strip.forEach(function (i) { inv.appendChild(paintSectionStrip(i)); });
    col.appendChild(inv);

    if (d.plansWereSkipped) {
      col.appendChild(el("div", "note acc",
        "This scan was run without working out what would happen to each row, so no card " +
        "below says what it would do and nothing has been held back as unsupported."));
    }

    if (d.incomplete && d.incomplete.length) {
      var warn = el("div", "note warn");
      warn.appendChild(el("div", null, "Some of what this tool reads could not be read:"));
      d.incomplete.forEach(function (s) {
        warn.appendChild(el("div", null, s.Name + " [" + s.Status + "]: " + s.Reason));
      });
      col.appendChild(warn);
    }

    // Kept apart from the list above on purpose: a refusal is a decision this
    // project made, not something that went wrong on this machine.
    if (d.refused && d.refused.length) {
      var refused = el("div", "note");
      refused.appendChild(el("div", null,
        "Refused by design, on every machine, whatever the privilege level:"));
      d.refused.forEach(function (s) {
        refused.appendChild(el("div", null, s.Name + ": " + s.Reason));
      });
      col.appendChild(refused);
    }

    // THE NOTES BELONG TO THE SECTIONS THAT WROTE THEM. The payload carries
    // both halves on the same row -- Title is the section's name, Note is that
    // section's own notes -- and the console prints each note under its own
    // section. Running them together into one list threw an association away
    // that the data already had, and left nine identical bars.
    //
    // Order is the payload's: sections in inventory order, notes in the order
    // the section wrote them. Nothing here sorts, ranks, filters or rewords
    // them; a section with nothing to say contributes nothing.
    //
    // The two blocks above are not notes and are not folded in here: one is a
    // refusal this project made and the other is what could not be read.
    (d.strip || []).forEach(function (i) {
      var note = i.Note || [];
      if (!note.length) { return; }

      col.appendChild(el("p", "nhd", i.Title));
      var group = el("div", "note");
      note.forEach(function (line) { group.appendChild(el("div", null, line)); });
      col.appendChild(group);
    });

    return col;
  }

  // ---- the category tables ------------------------------------------------

  // Four classes, four looks. Protected and Not offered are DIFFERENT LOOKS and
  // not one "not a decision" look: a rule held one back on purpose and nothing
  // was ever said about the other, and the console collapsing both into silence
  // is one of the things this window exists to fix.
  var CLASS_STRIPE = ["st-s", "st-a", "st-r", "st-n"];
  var CLASS_PILL = ["p-safe", "p-rev", "p-stop", "p-info"];

  function tableRowNode(t, index) {
    var r = t.Row[index];
    var tr = document.createElement("tr");

    t.Column.forEach(function (col, i) {
      var td = document.createElement("td");

      if (i === 0) {
        // The stripe is its own node and the name is its own node, so the
        // engine's string is not concatenated with anything on its way to the
        // DOM. The gap between them is a margin, not a space in the text.
        td.appendChild(el("span", "stripe-c " + CLASS_STRIPE[r.ClassIndex]));
        td.appendChild(el("span", "nm", r.Cell[i]));

        // The cross-reference: this object is in another table as well. It
        // says so and does nothing else -- it does not hide the row here, it
        // is not a link, and no control in either table acts on the other.
        if (r.AlsoIn && r.AlsoIn.length) {
          td.appendChild(el("span", "also", "also in " + r.AlsoIn.join(", ")));
        }

        td.className = "nmc";
        tr.appendChild(td);

        // SAFETY IS THE SECOND COLUMN AND NOT THE LAST ONE. These tables are
        // wider than the window -- an identity is not allowed to be shortened,
        // so the columns after it run off the right edge -- and the class is
        // the one thing that must be readable without scrolling sideways to
        // find it.
        var safety = document.createElement("td");
        safety.appendChild(el("span", "pill " + CLASS_PILL[r.ClassIndex], r.ClassLabel));
        tr.appendChild(safety);
        return;
      }

      td.textContent = r.Cell[i];

      if (col.IsNumeric) { td.className = "num dim"; }
      else if (col.IsIdentity) { td.className = "ident"; }
      else if (col.IsReason) { td.className = "rsn"; }
      else { td.className = "dim"; }

      tr.appendChild(td);
    });

    return tr;
  }

  function fillTableBody(t, node) {
    clear(node.body);
    t.Visible.forEach(function (index) {
      node.body.appendChild(tableRowNode(t, index));
    });

    node.shown.textContent = t.Visible.length === t.Row.length
      ? t.Row.length + " rows"
      : "showing " + t.Visible.length + " of " + t.Row.length;

    node.chip.forEach(function (c) {
      c.node.className = "chip" + (c.index === t.ClassIndex ? " on" : "");
    });

    node.head.forEach(function (h) {
      var on = h.index === t.SortColumn;
      h.node.className = (h.sortable ? "srt" : "") + (h.numeric ? " num" : "") + (on ? " on" : "");
      // A plain ASCII arrow: every file in this project is ASCII, and a
      // triangle glyph here would be one character above 0x7E.
      h.arrow.textContent = on ? (t.Descending ? "v" : "^") : "";
    });

    if (node.none) {
      node.none.hidden = t.Visible.length > 0;
    }
  }

  function paintTable(key) {
    var t = tableByKey[key];
    var col = el("div", "tcol");

    if (!t) {
      col.appendChild(el("p", "tnone", "That list is not in this scan."));
      return col;
    }

    var head = el("div", "thead");
    head.appendChild(el("h2", "view", t.Title));

    // The section's own opening sentences, verbatim, exactly as the strip under
    // the queue carries them. Nothing on this screen is worded here.
    var sub = el("div", "sub");
    (t.Headline || []).forEach(function (line) { sub.appendChild(el("div", null, line)); });
    head.appendChild(sub);

    var chips = el("div", "chips");
    var chipNode = [];
    (t.Chip || []).forEach(function (c) {
      var button = el("button", "chip");
      button.appendChild(el("span", null, c.Label));
      button.appendChild(el("span", "c", String(c.Count)));
      button.addEventListener("click", function () { sendTable(key, null, c.ClassIndex); });
      chips.appendChild(button);
      chipNode.push({ node: button, index: c.ClassIndex });
    });
    head.appendChild(chips);

    var find = el("div", "find");
    var box = document.createElement("input");
    box.type = "text";
    box.placeholder = "Filter by name or identity";
    box.value = t.Query || "";
    box.addEventListener("input", function () { sendTable(key, box.value, t.ClassIndex); });
    find.appendChild(box);
    var shown = el("span", "shown");
    find.appendChild(shown);
    head.appendChild(find);

    // Provenance, and only where there is any. Both of these are zero on every
    // un-elevated run measured so far, and neither may be silent if it is not:
    // a flagged row this section's inventory does not hold would otherwise be
    // a finding that is simply missing from its own table.
    if (t.FindingNotInInventory && t.FindingNotInInventory.length) {
      head.appendChild(el("div", "note warn",
        t.FindingNotInInventory.length + " flagged " +
        (t.FindingNotInInventory.length === 1 ? "row is" : "rows are") +
        " not in this list's inventory, so they are not drawn below: " +
        t.FindingNotInInventory.join(", ") + ". They are still in the queue."));
    }

    if (t.FlaggedWithNoRow) {
      head.appendChild(el("div", "note warn",
        t.FlaggedWithNoRow + " flagged " + (t.FlaggedWithNoRow === 1 ? "entry" : "entries") +
        " below could not be matched to a row, and " +
        (t.FlaggedWithNoRow === 1 ? "is" : "are") + " shown as needing review."));
    }

    col.appendChild(head);

    var scroll = el("div", "tscroll");
    var table = document.createElement("table");
    var thead = document.createElement("thead");
    var hrow = document.createElement("tr");
    var headNode = [];

    t.Column.forEach(function (c, i) {
      var th = document.createElement("th");
      th.appendChild(el("span", null, c.Label));
      var arrow = el("span", "ar");
      th.appendChild(arrow);

      if (c.IsSortable) {
        th.addEventListener("click", function () { send({ action: "sort", key: key, column: i }); });
      }

      hrow.appendChild(th);
      headNode.push({ node: th, arrow: arrow, index: i, sortable: c.IsSortable, numeric: c.IsNumeric });

      // The class column goes in beside the name, where the rows put it. It is
      // not one of the engine's columns and it has no sort of its own -- the
      // chips above the table are the control for it.
      if (i === 0) { hrow.appendChild(el("th", "sfty", "Safety")); }
    });

    thead.appendChild(hrow);
    table.appendChild(thead);

    var body = document.createElement("tbody");
    table.appendChild(body);
    scroll.appendChild(table);

    var none = el("p", "tnone", "Nothing in this list matches those filters.");
    scroll.appendChild(none);

    col.appendChild(scroll);

    tableNode[key] = { body: body, chip: chipNode, head: headNode, shown: shown, none: none };
    fillTableBody(t, tableNode[key]);

    return col;
  }

  // WHAT WAS TYPED OR CLICKED, AND NOTHING ELSE. Which rows that leaves, in
  // what order, and what the text is matched against are all worked out in
  // Gui.Core -- this asks, and paints the answer.
  function sendTable(key, query, classIndex) {
    var t = tableByKey[key];
    send({
      action: "table",
      key: key,
      query: query === null || query === undefined ? (t ? t.Query : "") : query,
      classIndex: classIndex
    });
  }

  // A FILTER OR A SORT CHANGE UPDATES THE SCREEN THAT IS ALREADY THERE, for the
  // same reason a selection does: .tscroll is the scroller, and a render()
  // would build a new one at the top and take the focus off the text box that
  // was being typed into. Only the rows, the chips, the arrows and the count
  // line change.
  function applyTable(d) {
    var t = tableByKey[d.key];
    if (!t) { return; }

    t.Query = d.query;
    t.ClassIndex = d.classIndex;
    t.SortColumn = d.sortColumn;
    t.Descending = d.descending;
    t.Visible = d.visible || [];

    var node = tableNode[d.key];
    if (node) { fillTableBody(t, node); }
  }

  // ---- failure ------------------------------------------------------------

  function paintFailure(d) {
    var col = el("div", "col");
    var box = el("div", "fail");

    box.appendChild(el("h2", "view", "The scan did not finish"));
    box.appendChild(el("p", "sub", d.message));

    var detail = [];
    if (d.errorPhase) { detail.push("Phase: " + d.errorPhase); }
    if (d.errorType) { detail.push("Error: " + d.errorType); }
    if (d.errorMessage) { detail.push(d.errorMessage); }
    if (d.exitCode !== null && d.exitCode !== undefined) { detail.push("Exit code: " + d.exitCode); }
    (d.standardError || []).forEach(function (line) { detail.push(line); });

    if (detail.length) { box.appendChild(el("div", "detail", detail.join("\n"))); }

    box.appendChild(el("div", "note",
      "This is not an empty result. Nothing on this PC has been changed, and nothing about " +
      "it is being reported as measured when it was not."));

    col.appendChild(box);
    return col;
  }

  // ---- action bar ---------------------------------------------------------

  function paintActionBar() {
    var abar = document.getElementById("abar");
    clear(abar);

    if (state.screen !== "decisions") {
      abar.appendChild(el("span", "cnt",
        state.screen === "scanning"
          ? "Scanning - nothing on this PC has been changed."
          : "Nothing on this PC has been changed."));
      return;
    }

    var cnt = el("span", "cnt");
    if (state.count) {
      cnt.appendChild(el("b", null, String(state.count)));
      cnt.appendChild(document.createTextNode(" selected"));
    } else {
      cnt.textContent = "Nothing selected";
    }
    abar.appendChild(cnt);

    abar.appendChild(el("span", "cnt",
      "Selection is not carried anywhere in this build. Nothing here acts."));

    var sp = el("span", "sp");

    // DISABLED, ON PURPOSE, AND WIRED TO NOTHING. It posts no message and has
    // no listener.
    //
    // This is not the dead left rail this shell dropped, and the difference is
    // the reason both calls stand. The rail was four enabled-looking links to
    // four screens that do not exist -- a UI promising a place to go. This is
    // one control, visibly disabled, naming what a selection is for, with the
    // sentence that says nothing here acts sitting beside it. The screen
    // otherwise ends at "4 selected" with nothing to press and only prose to
    // explain why, which reads as something broken rather than something not
    // built yet.
    var apply = el("button", "btn pri", "Review and apply");
    apply.disabled = true;
    sp.appendChild(apply);

    var clearBtn = el("button", "btn", "Clear");
    clearBtn.disabled = !state.count;
    clearBtn.addEventListener("click", function () { send({ action: "clear" }); });
    sp.appendChild(clearBtn);
    abar.appendChild(sp);
  }

  // ---- render -------------------------------------------------------------

  // THE ONLY THREE THINGS THAT CALL THIS are the first paint, a host message
  // carrying a new screen (scanning, decisions or failure -- each one a
  // different run state), and rail navigation. Every one of them is a new
  // screen rather than a change to the one on display, which is the rule
  // report 21 section 13.1 was written to keep: a render() throws away the
  // scroller, so anything that only CHANGES what is on screen -- a selection,
  // a filter, a sort -- updates in place instead.
  function render() {
    var main = document.getElementById("main");
    var rail = document.getElementById("rail");
    clear(main);

    // The maps die with the nodes they point at, in the same statement pair.
    cardNode = {};
    tableNode = {};

    if (state.screen === "decisions") {
      paintTitleBar(state.data);
      rail.hidden = false;
      paintRail();
      main.appendChild(state.view === "decisions"
        ? paintDecisions(state.data)
        : paintTable(state.view));
    } else if (state.screen === "failure") {
      paintTitleBar(null);
      rail.hidden = true;
      clear(rail);
      main.appendChild(paintFailure(state.data));
    } else {
      paintTitleBar(null);
      rail.hidden = true;
      clear(rail);
      main.appendChild(paintScanning(state.data || { phase: [], fraction: 0 }));
    }

    paintActionBar();
  }

  function setSelected(keys) {
    state.selected = {};
    (keys || []).forEach(function (k) { state.selected[k] = true; });
    state.count = (keys || []).length;
  }

  // A SELECTION CHANGE UPDATES THE SCREEN THAT IS ALREADY THERE. It must not
  // render(): the scroller is the .col that a render builds, so rebuilding it
  // scrolls the view back to the top, closes every open plan fold and takes
  // the focus off the button that was just pressed. Selecting something the
  // user had to scroll to would move it out from under them.
  //
  // The action bar is outside the scroller and holds no scroll position, so it
  // is repainted whole.
  function applySelection() {
    for (var key in cardNode) {
      if (Object.prototype.hasOwnProperty.call(cardNode, key)) {
        paintSelectedLook(cardNode[key]);
      }
    }
    paintActionBar();
  }

  if (window.chrome && window.chrome.webview) {
    window.chrome.webview.addEventListener("message", function (e) {
      var d = e.data;
      if (!d || !d.screen) { return; }

      if (d.screen === "selection") {
        setSelected(d.selected);
        applySelection();
        return;
      }

      // Neither is a table message: it is the answer to one control on one
      // table, and the screen it belongs to is already drawn.
      if (d.screen === "table") {
        applyTable(d);
        return;
      }

      // A decisions message is a new scan, not a change to this one, so it
      // does render the screen from nothing -- and the rail goes back to the
      // queue, because the screen the rail was pointing at is a screen from a
      // scan that is over.
      if (d.screen === "decisions") {
        setSelected(d.selected);
        state.view = "decisions";
        tableByKey = {};
        (d.table || []).forEach(function (t) { tableByKey[t.SectionKey] = t; });
      }

      state.screen = d.screen;
      state.data = d;
      render();
    });
  }

  render();
})();
