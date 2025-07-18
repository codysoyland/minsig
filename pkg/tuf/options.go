package tuf

import "time"

// Options contains parameters for TUF client creation
type Options struct {
	URL                string
	RootPath           string
	CachePath          string
	CacheTTL           time.Duration
	DisableLocalCache  bool
	Verbose            bool
}

// UpdateOptions contains parameters for TUF cache updates
type UpdateOptions struct {
	Force   bool
	Verbose bool
}