package helpers

import (
	"time"

	"github.com/ICL-ml4csec/msc-hmj24/checksignature/output"
	"github.com/ICL-ml4csec/msc-hmj24/checksignature/types"
)

// CreateTimeRange creates a time range for dependency checks based on the configuration
func CreateTimeRange(timeCutoff *time.Time) *output.TimeRange {
	if timeCutoff != nil {
		return &output.TimeRange{
			From: *timeCutoff,
			To:   time.Now(),
		}
	}
	return nil
}

// CreateKeyAgeRange creates a time range for key age checks based on the configuration
func CreateKeyAgeRange(config types.LocalCheckConfig) *output.TimeRange {
	if config.KeyCreationCutoff != nil {
		return &output.TimeRange{
			From: *config.KeyCreationCutoff,
			To:   time.Now(),
		}
	}
	return nil
}
