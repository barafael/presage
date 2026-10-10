-- The identity a client requires for sending to a contact (e.g. one the user verified): until it
-- is unpinned, a different identity of theirs isn't trusted for sending. Receiving is unaffected.
CREATE TABLE IF NOT EXISTS pinned_identities (
  address TEXT PRIMARY KEY NOT NULL,
  record BLOB NOT NULL
);
