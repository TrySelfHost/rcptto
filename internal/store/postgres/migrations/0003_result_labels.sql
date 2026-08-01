-- 0003_result_labels: carry the client name from an uploaded list through to
-- results, so a verified list can be matched back to the sheet it came from.

ALTER TABLE job_results ADD COLUMN IF NOT EXISTS label TEXT NOT NULL DEFAULT '';
