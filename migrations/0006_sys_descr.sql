-- Quality: keep the raw SNMP `sysDescr` in its own column so a derived,
-- concise `os_name` can be presented without losing the original banner.
ALTER TABLE assets ADD COLUMN sys_descr TEXT;
