dnl defined_bool(name) -- project-specific helper (not from GNU m4):
dnl expands to 1 if the macro `name` is defined, 0 otherwise, so that
dnl `defined_bool` results can be combined in `eval` boolean expressions.
define(<!defined_bool!>, <!ifdef(<!$1!>, <!1!>, <!0!>)!>)
