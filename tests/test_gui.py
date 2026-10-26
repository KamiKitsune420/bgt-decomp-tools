"""
Checks for the wxPython front end -- mostly that it is usable without seeing it.

These games are audio games, so a control a screen reader reads as "edit" or
"button" is a control nobody can use. That is a property worth asserting rather
than eyeballing once, because it is the kind of thing a later layout change
breaks silently: the window still looks right.

The frame is built for real (wx needs a display, so the whole module skips
where there is none) and then inspected. Nothing here clicks anything; the jobs
themselves are the CLI's code and are tested through it.

Run:  python -m pytest tests/test_gui.py -q
"""

import os
import sys

import pytest

try:                                   # after `pip install -e .`
    from bgtdecomp import bgt_gui
except ImportError:                    # straight from a checkout
    TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
    sys.path.insert(0, TOOLS)
    import bgt_gui

wx = bgt_gui.wx
pytestmark = pytest.mark.skipif(wx is None, reason="wxPython is not installed")


#: what `wx` names a control when nobody named it -- taken from wx itself
#: rather than guessed, since `CheckBox` defaults to "check" and not
#: "checkbox", and a list that is merely plausible would let the real case
#: through.
GENERIC_NAMES = {"", "text", "button", "check", "choice", "listbox",
                 "radiobutton", "control", "panel", "staticText", "frame"}


@pytest.fixture(scope="module")
def frame():
    """One real frame for the whole module.

    wx permits a single `App` per process and does not enjoy being torn down
    and rebuilt, so the frame is made once, never shown, and destroyed at the
    end.
    """
    try:
        app = wx.App(False)
    except Exception as exc:                        # no display, usually
        pytest.skip("wx could not start: %s" % exc)
    window = bgt_gui.Frame()
    yield window
    window.Destroy()
    app.Destroy()


def _interactive(window):
    """Every control a keyboard can land on, with its class and name."""
    found = []

    def walk(parent):
        for child in parent.GetChildren():
            if isinstance(child, (wx.TextCtrl, wx.Button, wx.CheckBox,
                                  wx.Choice, wx.ListBox, wx.RadioButton)):
                found.append(child)
            walk(child)

    walk(window)
    return found


def test_every_interactive_control_has_a_name(frame):
    """A control that reads as "edit" cannot be filled in by someone who
    cannot see which row it is on.

    `wx` defaults a control's name to its class, so the check is that the name
    is not simply the class name -- which is exactly what a forgotten label
    looks like to a screen reader.
    """
    nameless = []
    for control in _interactive(frame):
        name = (control.GetName() or "").strip()
        label = (control.GetLabel() or "").strip()
        generic = name.lower() in GENERIC_NAMES
        if generic and not label:
            nameless.append("%s at %s" % (type(control).__name__,
                                          control.GetPosition()))
    assert not nameless, "controls a screen reader cannot announce: %s" % nameless


def test_the_log_is_reviewable_and_not_writable(frame):
    """The log is the one widget a screen reader can read back line by line,
    so it has to be a multiline read-only text box -- not a status bar, and
    not something the user can type into by accident."""
    log = frame.log
    assert log.IsMultiLine()
    assert not log.IsEditable()
    assert log.GetName() == "Progress and results"


def test_progress_is_appended_not_replaced(frame):
    """Nothing already said should be overwritten: the whole point of the log
    is that it can be reviewed after the job is over."""
    before = frame.log.GetValue()
    frame.say("first thing")
    frame.say("second thing")
    after = frame.log.GetValue()
    assert after.startswith(before)
    assert "first thing" in after and "second thing" in after
    assert after.index("first thing") < after.index("second thing")


def test_copying_and_extracting_are_exclusive(frame):
    """They are alternatives, and checking one clears the other rather than
    letting both be set and quietly preferring one at run time."""
    frame.with_data.SetValue(True)
    frame.extract_data.SetValue(True)
    event = wx.CommandEvent(wx.EVT_CHECKBOX.typeId, frame.extract_data.GetId())
    event.SetEventObject(frame.extract_data)
    frame._only_one_data_option(event)
    assert frame.extract_data.GetValue() and not frame.with_data.GetValue()

    frame.with_data.SetValue(True)
    event = wx.CommandEvent(wx.EVT_CHECKBOX.typeId, frame.with_data.GetId())
    event.SetEventObject(frame.with_data)
    frame._only_one_data_option(event)
    assert frame.with_data.GetValue() and not frame.extract_data.GetValue()


def test_there_is_no_button_that_claims_to_stop_a_job(frame):
    """`recover` has no cancellation point, and a Stop button that cannot stop
    is worse than none: it invites you to believe the output folder is
    consistent when it is not."""
    labels = [(c.GetLabel() or "").lower() for c in _interactive(frame)]
    assert not any("stop" in text or "cancel" in text or "abort" in text
                   for text in labels), labels


def test_the_window_disables_its_controls_while_working(frame):
    """A second job started on top of the first would write the same folder
    twice; disabling is how that is prevented, so it has to really disable."""
    frame.busy(True)
    assert not frame.recover_button.IsEnabled()
    assert not frame.exe.IsEnabled()
    frame.busy(False)
    assert frame.recover_button.IsEnabled()
    assert frame.exe.IsEnabled()
