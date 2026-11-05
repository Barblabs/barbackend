package agents

import (
	"bytes"
	"encoding/json"
	"fmt"

	"barbackend/internal/assessment"
	"barbackend/internal/inventory"
	"github.com/google/uuid"
)

// ParseFindings reads a list of Dossiers as docs/examples/findings.json holds,
// the shape the Findings pipeline hands the Prioritizer. A field the shape does
// not have is an error, so a mistake in building it is not silently dropped.
// Prioritize validates each Dossier.
func ParseFindings(raw []byte) ([]assessment.Dossier, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var findings []assessment.Dossier
	if err := decoder.Decode(&findings); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFindings, err)
	}
	return findings, nil
}

// ParseAsset reads an Asset described as docs/examples/asset.json, to build
// the Dossier of a Finding on one that no CMDB Source holds.
func ParseAsset(raw []byte) (*inventory.Asset, error) {
	var file struct {
		Name        string `json:"name"`
		Kind        string `json:"kind"`
		Criticality string `json:"criticality"`
		Exposure    string `json:"exposure"`
		Software    []struct {
			Role    string `json:"role"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Vendor  string `json:"vendor"`
			Product string `json:"product"`
		} `json:"software"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("read asset: %w", err)
	}
	kind, err := inventory.ParseAssetKind(file.Kind)
	if err != nil {
		return nil, err
	}
	params := inventory.ImportedAssetParams{Name: file.Name, Kind: kind, Software: make([]inventory.SoftwareComponent, len(file.Software))}
	if file.Criticality != "" {
		if params.Criticality, err = inventory.ParseCriticality(file.Criticality); err != nil {
			return nil, err
		}
	}
	for i, s := range file.Software {
		role, err := inventory.ParseSoftwareRole(s.Role)
		if err != nil {
			return nil, err
		}
		params.Software[i] = inventory.SoftwareComponent{Role: role, Name: s.Name, Version: s.Version, Product: inventory.Product{Vendor: s.Vendor, Name: s.Product}}
	}
	imported, err := inventory.NewImportedAsset(params)
	if err != nil {
		return nil, err
	}
	asset, err := inventory.NewAsset(inventory.SourceReference{Source: inventory.CMDBSourceID(uuid.New()), RecordID: file.Name}, imported)
	if err != nil {
		return nil, err
	}
	if file.Exposure == "" {
		return asset, nil
	}
	exposure, err := inventory.ParseExposure(file.Exposure)
	if err != nil {
		return nil, err
	}
	return asset, asset.DeclareExposure(exposure)
}
