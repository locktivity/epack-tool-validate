// Package raw defines YAML-mirroring structs for profile parsing.
// These types exist only for parsing - use compiled types for validation.
package raw

// RawProfile mirrors the YAML structure of a profile file.
type RawProfile struct {
	ID           string           `yaml:"id"`
	Name         string           `yaml:"name"`
	Version      string           `yaml:"version"`
	Description  string           `yaml:"description,omitempty"`
	Requirements []RawRequirement `yaml:"requirements"`
}

// RawRequirement represents a single requirement in the profile.
type RawRequirement struct {
	ID          string         `yaml:"id"`
	Control     string         `yaml:"control,omitempty"`
	Name        string         `yaml:"name"`
	Category    string         `yaml:"category,omitempty"`
	SatisfiedBy RawSatisfiedBy `yaml:"satisfied_by"`

	// SourceFile tracks where this requirement came from (base profile or overlay).
	// Not populated from YAML - set programmatically during parsing and overlay application.
	SourceFile string `yaml:"-" json:"-"`
}

// RawSatisfiedBy contains the clauses that can satisfy a requirement.
// Exactly one of AnyOf or AllOf must be set.
type RawSatisfiedBy struct {
	AnyOf []RawClause `yaml:"any_of,omitempty"`
	AllOf []RawClause `yaml:"all_of,omitempty"`
}

// RawClause represents a single satisfaction clause.
type RawClause struct {
	Type               string         `yaml:"type"`
	Severity           string         `yaml:"severity,omitempty"` // "critical"|"high"|"medium"|"low" OR empty=pass
	Freshness          *RawFreshness  `yaml:"freshness,omitempty"`
	MetadataConditions *RawConditions `yaml:"metadata_conditions,omitempty"`
}

// RawFreshness specifies freshness requirements.
type RawFreshness struct {
	MaxAgeDays int `yaml:"max_age_days"`
}

// RawConditions contains the conditions to evaluate.
type RawConditions struct {
	All []RawCondition `yaml:"all,omitempty"`
}

// RawCondition represents a single condition to check against artifact data.
type RawCondition struct {
	Path        string `yaml:"path"`
	Op          string `yaml:"op"`
	Value       any    `yaml:"value"`
	Cardinality string `yaml:"cardinality,omitempty"` // "all"|"any"|"none" for multi-value paths
}

// RawOverlay mirrors the YAML structure of an overlay file.
type RawOverlay struct {
	ID          string           `yaml:"id,omitempty"`
	Name        string           `yaml:"name,omitempty"`
	Description string           `yaml:"description,omitempty"`
	Modify      []RawModify      `yaml:"modify,omitempty"`
	Skip        []string         `yaml:"skip,omitempty"`
	Add         []RawRequirement `yaml:"add,omitempty"`

	// SourceFile tracks where this overlay came from.
	// Not populated from YAML - set programmatically after parsing.
	SourceFile string `yaml:"-" json:"-"`
}

// RawModify specifies a requirement to modify.
type RawModify struct {
	ID          string          `yaml:"id"`
	Control     string          `yaml:"control,omitempty"`
	Name        string          `yaml:"name,omitempty"`
	Category    string          `yaml:"category,omitempty"`
	SatisfiedBy *RawSatisfiedBy `yaml:"satisfied_by,omitempty"`
}
