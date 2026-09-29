-- v1.1 job outcome completeness (PostgreSQL): discovery jobs record the
-- counts of every observation kind they persist, not only assets and
-- services.

ALTER TABLE discovery_jobs ADD COLUMN filesystems_found BIGINT;
ALTER TABLE discovery_jobs ADD COLUMN running_services_found BIGINT;
ALTER TABLE discovery_jobs ADD COLUMN connections_found BIGINT;
