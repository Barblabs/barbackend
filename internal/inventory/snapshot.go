package inventory

// Snapshot is every in-scope record of a CMDB Source at one point in time,
// plus the records its CMDB Provider could not turn into imported values.
// Reconcile validates it, so it has no constructor.
type Snapshot struct {
	// Areas is every Area of the CMDB Source, complete like Records, so an
	// Area missing from it is no longer in the source.
	Areas   []AreaRecord
	Records []Record
	Skipped []SkippedRecord
}

type Record struct {
	RecordID string
	Imported ImportedAsset
}

type SkippedRecord struct {
	RecordID string
	Reason   string
}

type AreaRecord struct {
	RecordID string
	Imported ImportedArea
}
