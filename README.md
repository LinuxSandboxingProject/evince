# evince
Sandboxed Evince Document Viewer

This is a sandboxed version of the evince Document Viewer using seccomp filter (libseccomp)

The original application can be found here: https://wiki.gnome.org/Apps/Evince


Todo
----

- fix/clean makefiles
- prevent evince to try to open external links (causes crash)
- restructure evince process handling to further restrict seccomp filter


Goal
----

Before the application reads/renders the target document file, the list of allowed systemcalls should be near zero.
