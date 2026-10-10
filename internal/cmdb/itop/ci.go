package itop

// ci is a configuration item of an in-scope iTop class, as read before
// mapping. Fields hold iTop's raw values: "" for a blank string or a blank
// external key's name, and a nil criticality for the JSON null iTop returns
// when business_criticity is blank.
//
//nolint:unused // scaffold, read once fetch and mapping land
type ci struct {
	key          string
	class        string
	name         string
	description  string
	status       string
	criticality  *string
	brand        string
	model        string
	osFamily     string
	osVersion    string
	iosVersionID string
	contacts     []contact
	instances    []instance
}

//nolint:unused // scaffold, read once fetch and mapping land
type contact struct {
	id    string
	class string
}

// instance is a SoftwareInstance linked to a ci. softwareID is "0" when it
// links to no Software.
//
//nolint:unused // scaffold, read once fetch and mapping land
type instance struct {
	class      string
	name       string
	softwareID string
}

//nolint:unused // scaffold, read once fetch and mapping land
type software struct {
	name    string
	version string
}

// iosVersion is a Network Device's operating system, named by its brand
// because iTop stores no OS name for it.
//
//nolint:unused // scaffold, read once fetch and mapping land
type iosVersion struct {
	brand   string
	version string
}

// lookups holds the records the cis reference by id, read in bulk.
//
//nolint:unused // scaffold, read once fetch and mapping land
type lookups struct {
	emails      map[string]string
	software    map[string]software
	iosVersions map[string]iosVersion
}
