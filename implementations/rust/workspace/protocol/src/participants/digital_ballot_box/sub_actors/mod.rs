/*!
Sub-actor implementations for the Digital Ballot Box.

Each sub-actor handles one type of protocol interaction:
- `submission` - Ballot submission protocol
- `casting` - Ballot casting protocol
- `checking` - Ballot checking protocol (forwarding between BCA and VA)
*/

pub mod casting;
pub mod checking;
pub mod submission;
