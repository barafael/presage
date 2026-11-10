-- Work owed after a message, kept until done. An upserted job keeps its id but starts over.
CREATE TABLE jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  job TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  due_at INTEGER NOT NULL DEFAULT 0
);
