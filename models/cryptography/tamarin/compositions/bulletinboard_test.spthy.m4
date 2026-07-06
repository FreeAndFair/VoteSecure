
dnl
dnl This is the m4 input file for the composition of the bulletin
dnl board and a basic test of its executability.
dnl
dnl @author Daniel M. Zimmerman
dnl @copyright Free & Fair 2025-26
dnl @version 0.2
dnl
dnl We change the m4 quote characters to <! and !>, so that they don't
dnl interfere with Tamarin's quote characters or any comments we might
dnl want to write. The incantation below makes that change, and prevents
dnl us from doing it in the included files by defining QUOTE_CHANGED.
dnl
define(`QUOTE_CHANGED')
changequote(`<!', `!>')
dnl
dnl This particular composition is uncomplicated; it only includes
dnl the bulletin board primitives and rules that instantiate bulletin
dnl boards.
dnl
/*
  Bulletin Board Test

  This theory is a "test" of the bulletin board primitives, which
  instantiates bulletin boards and has a number of executability
  properties.

  @author Daniel M. Zimmerman
  @copyright Free & Fair 2025-26
  @version 0.2
*/

theory bulletinboard_instantiation

begin

include(common/bulletinboard.m4.inc)
include(other/bulletinboard_instantiation.spthy.inc)

end
