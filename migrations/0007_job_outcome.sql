-- v1.1 job outcome completeness: discovery jobs record the counts of every
-- observation kind they persist, not only assets and services.

ALTER TABLE discovery_jobs ADD COLUMN filesystems_found INTEGER;
ALTER TABLE discovery_jobs ADD COLUMN running_services_found INTEGER;
ALTER TABLE discovery_jobs ADD COLUMN connections_found INTEGER;
