package itop

// ci is a configuration item of an in-scope iTop class, decoded from its
// JSON fields before mapping. Fields hold iTop's raw values: "" for a blank
// string or a blank external key's name, and a nil Criticality for the JSON
// null iTop returns when business_criticity is blank. Key and Class come from
// the object envelope, not from the fields.
type ci struct {
	Key          string     `json:"-"`
	Class        string     `json:"-"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Status       string     `json:"status"`
	Criticality  *string    `json:"business_criticity"`
	Brand        string     `json:"brand_name"`
	Model        string     `json:"model_name"`
	OSFamily     string     `json:"osfamily_name"`
	OSVersion    string     `json:"osversion_name"`
	IOSVersionID string     `json:"iosversion_id"`
	Contacts     []contact  `json:"contacts_list"`
	Instances    []instance `json:"softwares_list"`
}

type contact struct {
	ID    string `json:"contact_id"`
	Class string `json:"contact_id_finalclass_recall"`
}

// instance is a SoftwareInstance linked to a ci. SoftwareID is "0" when it
// links to no Software.
type instance struct {
	Class      string `json:"finalclass"`
	Name       string `json:"name"`
	SoftwareID string `json:"software_id"`
}

// person, software and iosVersion are the records the cis reference by id,
// decoded from their JSON fields like a ci.
type person struct {
	Email string `json:"email"`
}

type software struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// iosVersion is a Network Device's operating system. iTop stores no OS name
// for it, so it is named by its brand and its Name is the version.
type iosVersion struct {
	Brand string `json:"brand_name"`
	Name  string `json:"name"`
}

// lookups holds the records the cis reference by id, read in bulk.
type lookups struct {
	persons     map[string]person
	software    map[string]software
	iosVersions map[string]iosVersion
}
