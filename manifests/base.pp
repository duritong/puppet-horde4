# manage horde main deps
class horde4::base {
  # all the php deps
  # are anyway in the scl parts
  include aspell
  include gpg
  require git
}
