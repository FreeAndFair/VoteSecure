divert(<!-1!>)
# foreach(x, (item_1, item_2, ..., item_n), stmt)
#   parenthesized list, simple version
#
# Adapted from the `foreach` example in the GNU m4 manual (see the
# "Loops and recursion" section of the GNU m4 Info pages), modified to
# use this project's `<! !>` quoting convention instead of the default
# m4 quoting.
define(<!foreach!>, <!pushdef(<!$1!>)_foreach($@)popdef(<!$1!>)!>)
define(<!_arg1!>, <!$1!>)
define(<!_foreach!>, <!ifelse(<!$2!>, <!()!>, <!!>,
  <!define(<!$1!>, _arg1$2)$3<!!>$0(<!$1!>, (shift$2), <!$3!>)!>)!>)
divert<!!>dnl
