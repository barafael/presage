-- The sender key each group's messages go with, and the devices it was sent to
-- (Signal-Android's `distribution_id` and `sender_key_shared`).
CREATE TABLE IF NOT EXISTS group_sender_keys (
  master_key BLOB NOT NULL PRIMARY KEY,
  distribution_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sender_key_shared (
  distribution_id TEXT NOT NULL,
  service_id TEXT NOT NULL,
  device_id INTEGER NOT NULL,
  registration_id INTEGER NOT NULL,
  PRIMARY KEY (distribution_id, service_id, device_id)
);
