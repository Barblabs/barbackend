package agents

import (
	"bytes"
	"encoding/json"
	"fmt"

	"barbackend/internal/assessment"
)

// ParseFindings reads a list of Dossiers as docs/examples/findings.json holds,
// the shape Dossiers have, to run the Agents on Findings no Customer has. A
// field the shape does not have is an error, so a mistake in building it is
// not silently dropped. Crew.Prioritize validates each Dossier.
func ParseFindings(raw []byte) ([]assessment.Dossier, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var findings []assessment.Dossier
	if err := decoder.Decode(&findings); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFindings, err)
	}
	return findings, nil
}
