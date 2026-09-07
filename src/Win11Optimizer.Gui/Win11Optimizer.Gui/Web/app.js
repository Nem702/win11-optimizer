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

  var state = { screen: "scanning", data: null, selected: {}, count: 0 };

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

    (d.phase || []).forEach(function (p) {
      var phaseState = p.State === 2 ? "done" : (p.State === 1 ? "now" : "");
      var row = el("div", "ph" + (phaseState ? " " + phaseState : ""));
      row.appendChild(el("span", null, p.Label));
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

  function paintInventoryRow(i) {
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

    return row;
  }

  function paintDecisions(d) {
    var col = el("div", "col");

    col.appendChild(el("h2", "view",
      (d.card.length === 1 ? "1 decision" : d.card.length + " decisions") +
      ", from " + d.inventory.length + " lists"));
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
    d.inventory.forEach(function (i) { inv.appendChild(paintInventoryRow(i)); });
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
    (d.inventory || []).forEach(function (i) {
      var note = i.Note || [];
      if (!note.length) { return; }

      col.appendChild(el("p", "nhd", i.Title));
      var group = el("div", "note");
      note.forEach(function (line) { group.appendChild(el("div", null, line)); });
      col.appendChild(group);
    });

    return col;
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

  function render() {
    var main = document.getElementById("main");
    clear(main);

    // The map dies with the nodes it points at, in the same statement pair.
    cardNode = {};

    if (state.screen === "decisions") {
      paintTitleBar(state.data);
      main.appendChild(paintDecisions(state.data));
    } else if (state.screen === "failure") {
      paintTitleBar(null);
      main.appendChild(paintFailure(state.data));
    } else {
      paintTitleBar(null);
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

      // A decisions message is a new scan, not a change to this one, so it
      // does render the screen from nothing.
      if (d.screen === "decisions") { setSelected(d.selected); }

      state.screen = d.screen;
      state.data = d;
      render();
    });
  }

  render();
})();
