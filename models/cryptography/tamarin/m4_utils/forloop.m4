divert(<!-1!>)
# forloop(var, from, to, stmt)
#
# Adapted from the `forloop` example in the GNU m4 manual (see the
# "Loops and recursion" section of the GNU m4 Info pages), modified to
# use this project's `<! !>` quoting convention instead of the default
# m4 quoting.
define(<!forloop!>, <!ifelse(eval(<!($2) <= ($3)!>), <!1!>,
  <!pushdef(<!$1!>)_$0(<!$1!>, eval(<!$2!>),
    eval(<!$3!>), <!$4!>)popdef(<!$1!>)!>)!>)
define(<!_forloop!>,
  <!define(<!$1!>, <!$2!>)$4<!!>ifelse(<!$2!>, <!$3!>, <!!>,
    <!$0(<!$1!>, incr(<!$2!>), <!$3!>, <!$4!>)!>)!>)
divert<!!>dnl
