"""
bgt_gui -- a wxPython front end for `bgt identify`, `bgt recover` and `bgt compile`.

The whole toolkit is a command line, and the command line stays the reference:
this window calls exactly the same `bgt_project.recover`, `engine.identify` and
`bgt_compile.check` the CLI does, with the same defaults, so anything it can do
can be reproduced in one command and anything it reports can be checked there.

## Why it is built the way it is

These are audio games, and the people who want their source back read screens
with a screen reader. That is a design constraint, not a nicety, and it decides
most of what follows:

* **Standard controls only.** Every widget here is a stock `wx` control with a
  real label. Nothing is custom-drawn, nothing conveys state by colour alone,
  and there is no control whose meaning depends on where it sits.
* **A label for every field, as a sibling and as a name.** A `wx.StaticText`
  immediately before the control gives the visual label; `SetName` gives the
  accessible one. Both, because which of the two a screen reader picks up
  varies, and a field that reads as "edit" is a field nobody can fill in.
* **The log is a read-only multiline text box**, not a list or a status bar,
  because that is the one widget a screen reader can review line by line after
  the fact. Progress is appended to it rather than replacing a label, so
  nothing that was said is lost.
* **Finishing raises a dialog.** A screen reader announces a dialog without
  being asked; it does not announce a label that quietly changed. So the end
  of a long job -- which is the thing you were waiting for -- arrives as a
  message box, and the detail stays in the log.
* **The work runs on a thread**, and every touch of a widget from it goes
  through `wx.CallAfter`. Recovering Crazy Party takes minutes; a frozen window
  is unreadable, and a screen reader cannot even tell you it is still working.

There is deliberately no Stop button. `recover` has no cancellation point, and
a button that claims to stop something it cannot stop is worse than no button:
the honest version is that the controls disable while a job runs and the log
says what is happening.
"""
from __future__ import annotations

import os
import sys
import threading
import traceback

try:                      # installed as a package
    from . import bgt_compile, bgt_project, engine
except ImportError:       # run directly from a checkout
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import bgt_compile
    import bgt_project
    import engine

try:
    import wx
except ImportError:                                   # pragma: no cover
    wx = None


WILDCARD = "Game executable (*.exe)|*.exe|All files (*.*)|*.*"
SCRIPT_WILDCARD = "BGT script (*.bgt)|*.bgt|All files (*.*)|*.*"


def _labelled(parent, sizer, label, value="", wildcard=None, directory=False):
    """A labelled text field with a Browse button, as one row.

    Returns the `wx.TextCtrl`. The label is set twice on purpose -- once as the
    visible `StaticText` beside the field and once as the control's accessible
    name -- because a field that reads only as "edit" cannot be filled in by
    someone who cannot see which row it is on.
    """
    text = wx.StaticText(parent, label=label)
    field = wx.TextCtrl(parent, value=value)
    field.SetName(label.rstrip(":"))
    browse = wx.Button(parent, label="Browse %s..." % label.rstrip(":").lower())
    browse.SetName("Browse for %s" % label.rstrip(":").lower())

    def pick(_event):
        # Only pass a starting place that actually exists. An empty or bogus
        # path reaches the shell as one, and it answers with
        # `IShellItem::GetDisplayName failed` -- twice, on an empty field.
        start = (field.GetValue() or "").strip().strip('"')
        if directory:
            dialog = wx.DirDialog(parent, "Choose %s" % label.rstrip(":"),
                                  **({"defaultPath": start}
                                     if os.path.isdir(start) else {}))
        else:
            folder = os.path.dirname(start)
            dialog = wx.FileDialog(parent, "Choose %s" % label.rstrip(":"),
                                   wildcard=wildcard or WILDCARD,
                                   style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST,
                                   **({"defaultDir": folder}
                                      if os.path.isdir(folder) else {}))
        with dialog:
            if dialog.ShowModal() == wx.ID_OK:
                field.SetValue(dialog.GetPath())
                field.SetFocus()

    browse.Bind(wx.EVT_BUTTON, pick)

    row = wx.BoxSizer(wx.HORIZONTAL)
    row.Add(field, 1, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 6)
    row.Add(browse, 0)
    sizer.Add(text, 0, wx.TOP, 8)
    sizer.Add(row, 0, wx.EXPAND)
    return field


class Frame(wx.Frame):
    def __init__(self):
        super().__init__(None, title="BGT decompilation toolkit",
                         size=(760, 620))
        panel = wx.Panel(self)
        outer = wx.BoxSizer(wx.VERTICAL)
        body = wx.BoxSizer(wx.VERTICAL)

        self.exe = _labelled(panel, body, "Game executable:")
        self.out = _labelled(panel, body, "Output folder:", directory=True)

        options = wx.StaticBoxSizer(wx.VERTICAL, panel, "Options")
        box = options.GetStaticBox()
        self.compile_check = wx.CheckBox(
            box, label="Check the result with BGT's own compiler (slower)")
        self.with_data = wx.CheckBox(
            box, label="Copy the asset packs the script needs into the project")
        # On by default: without the packs the recovered game reports
        # `ERROR! could not load pack data/bgm.dat.` and plays no audio.
        self.with_data.SetValue(True)
        self.extract_data = wx.CheckBox(
            box, label="Also extract the packs' entries, decrypted, for reading")
        self.make_zip = wx.CheckBox(box, label="Also write a .zip of the project")
        self.make_zip.SetValue(True)
        for control in (self.compile_check, self.with_data,
                        self.extract_data, self.make_zip):
            options.Add(control, 0, wx.ALL, 4)
        # Copying and extracting are **not** alternatives, and forcing a
        # choice was a mistake: they answer different questions -- "can this
        # run?" and "what is in the pack?" -- so the obvious way to get the
        # assets out also produced a project with no audio.
        body.Add(options, 0, wx.EXPAND | wx.TOP, 10)

        buttons = wx.BoxSizer(wx.HORIZONTAL)
        self.identify_button = wx.Button(panel, label="&Identify engine")
        self.recover_button = wx.Button(panel, label="&Recover project")
        self.compile_button = wx.Button(panel, label="&Compile a script...")
        for button in (self.identify_button, self.recover_button,
                       self.compile_button):
            buttons.Add(button, 0, wx.RIGHT, 6)
        body.Add(buttons, 0, wx.TOP, 10)

        log_label = wx.StaticText(panel, label="Progress and results:")
        self.log = wx.TextCtrl(
            panel, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_DONTWRAP)
        self.log.SetName("Progress and results")
        body.Add(log_label, 0, wx.TOP, 10)
        body.Add(self.log, 1, wx.EXPAND | wx.TOP, 2)

        outer.Add(body, 1, wx.EXPAND | wx.ALL, 10)
        panel.SetSizer(outer)

        self.identify_button.Bind(wx.EVT_BUTTON, self.on_identify)
        self.recover_button.Bind(wx.EVT_BUTTON, self.on_recover)
        self.compile_button.Bind(wx.EVT_BUTTON, self.on_compile)
        self.Bind(wx.EVT_CLOSE, self.on_close)

        self.worker: threading.Thread | None = None
        # After the frame is on screen, not during construction: focusing a
        # window Windows has not realised yet fails with error 87, which wx
        # reports and the user never sees the point of.
        wx.CallAfter(self.exe.SetFocus)
        self.say("Ready. Choose a game executable and an output folder.")
        self.say("Everything here runs the same code as the `bgt` command "
                 "line, so any result can be reproduced with one command.")

    # -- plumbing ----------------------------------------------------------

    def say(self, message: str) -> None:
        """Append a line to the log, from any thread.

        Appending rather than replacing is the point: a screen reader reviews
        this box line by line afterwards, so nothing said should be overwritten.
        """
        def append():
            self.log.AppendText(message.rstrip() + "\n")
        if threading.current_thread() is threading.main_thread():
            append()
        else:
            wx.CallAfter(append)

    def busy(self, running: bool) -> None:
        for control in (self.identify_button, self.recover_button,
                        self.compile_button, self.exe, self.out,
                        self.compile_check, self.with_data,
                        self.extract_data, self.make_zip):
            control.Enable(not running)

    def run(self, what: str, job) -> None:
        """Run `job` off the main thread, then announce that it finished.

        The announcement is a dialog because that is what a screen reader
        reads without being asked; the detail is already in the log.
        """
        if self.worker is not None and self.worker.is_alive():
            wx.MessageBox("A job is already running. Wait for it to finish.",
                          "Busy", wx.OK | wx.ICON_INFORMATION, self)
            return
        self.busy(True)

        def wrapper():
            try:
                headline = job()
            except Exception as exc:                  # a GUI must not vanish
                self.say("")
                self.say("%s failed: %s" % (what, exc))
                for line in traceback.format_exc().splitlines():
                    self.say("    " + line)
                headline = "%s failed: %s" % (what, exc)
                icon = wx.ICON_ERROR
            else:
                icon = wx.ICON_INFORMATION
            wx.CallAfter(self.finished, what, headline or ("%s finished" % what), icon)

        self.worker = threading.Thread(target=wrapper, daemon=True)
        self.worker.start()

    def finished(self, what: str, headline: str, icon: int) -> None:
        self.busy(False)
        self.say("")
        wx.MessageBox(headline, what, wx.OK | icon, self)
        self.log.SetFocus()

    def on_close(self, event) -> None:
        if self.worker is not None and self.worker.is_alive():
            # There is no cancellation point inside `recover`, so say so
            # rather than pretend: closing now would leave it half written.
            if wx.MessageBox(
                    "A job is still running and cannot be interrupted.\n\n"
                    "Close anyway and leave the output folder unfinished?",
                    "Still working", wx.YES_NO | wx.ICON_WARNING, self) != wx.YES:
                return
        event.Skip()

    # -- the three jobs ----------------------------------------------------

    def _need(self, field, label: str) -> str:
        value = field.GetValue().strip().strip('"')
        if not value:
            wx.MessageBox("Choose %s first." % label, "Nothing to do",
                          wx.OK | wx.ICON_INFORMATION, self)
            field.SetFocus()
            return ""
        return value

    def on_identify(self, _event) -> None:
        path = self._need(self.exe, "a game executable")
        if not path:
            return

        def job():
            identity = engine.identify(path)
            self.say(identity.summary())
            for name, value in sorted(identity.facts.items()):
                if value is None:
                    continue          # a fact that does not apply is not news
                self.say("    %-18s %s" % (name, value))
            for name, why in sorted(identity.rejected.items()):
                self.say("    rejected %-9s %s" % (name, why))
            return identity.summary()

        self.run("Identify engine", job)

    def on_recover(self, _event) -> None:
        path = self._need(self.exe, "a game executable")
        if not path:
            return
        out = self._need(self.out, "an output folder")
        if not out:
            return
        if self.compile_check.GetValue() and bgt_compile.find_compiler() is None:
            wx.MessageBox("BGT was not found, so the compiler check cannot run.\n\n"
                          "Clear that option, or install BGT.",
                          "No compiler", wx.OK | wx.ICON_WARNING, self)
            return
        options = dict(make_zip=self.make_zip.GetValue(),
                       compile_check=self.compile_check.GetValue(),
                       with_data=self.with_data.GetValue(),
                       extract_data=self.extract_data.GetValue())

        def job():
            self.say("Recovering %s" % path)
            project = bgt_project.recover(path, out, progress=self.say, **options)
            self.say("")
            for line in project.summary().splitlines():
                self.say(line)
            report = project.compile_report
            if report is not None:
                return "Recovered %d files. The compiler says: %s" % (
                    len(project.files), report.summary())
            return "Recovered %d files to %s" % (len(project.files), out)

        self.run("Recover project", job)

    def on_compile(self, _event) -> None:
        if bgt_compile.find_compiler() is None:
            wx.MessageBox("BGT was not found, so nothing can be compiled.",
                          "No compiler", wx.OK | wx.ICON_WARNING, self)
            return
        with wx.FileDialog(self, "Choose a script to compile",
                           wildcard=SCRIPT_WILDCARD,
                           style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) as dialog:
            if dialog.ShowModal() != wx.ID_OK:
                return
            script = dialog.GetPath()

        def job():
            self.say("Compiling %s" % script)
            # Through the same staged copy the CLI uses: `main` disarmed, the
            # copy beside the script so its includes and its data still
            # resolve, and both the copy and the executable the compiler
            # writes cleaned up afterwards.
            report = bgt_compile.check_project(script)
            for diagnostic in report.diagnostics:
                self.say("  %-8s %s:%s  %s" % (diagnostic.kind.lower(),
                                               os.path.basename(diagnostic.file),
                                               diagnostic.line,
                                               diagnostic.message))
            return report.summary()

        self.run("Compile a script", job)


def main(argv=None) -> int:
    if wx is None:
        print("bgt gui: wxPython is not installed -- pip install wxPython",
              file=sys.stderr)
        return 2
    app = wx.App(False)
    Frame().Show()
    app.MainLoop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
