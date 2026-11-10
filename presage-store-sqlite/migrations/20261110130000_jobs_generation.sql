-- How often another job took a job's place under its key: a run settles only the job it began with.
ALTER TABLE jobs ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
