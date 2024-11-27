package gomwan

import "errors"

var (
	// ErrEmptyInterfaces is returned when the interfaces slice is empty
	ErrEmptyInterfaces      = errors.New("gomwan: interfaces slice is empty")
	ErrNoWans               = errors.New("gomwan: no WAN interfaces found")
	ErrNoLans               = errors.New("gomwan: no LAN interfaces found")
	ErrWansWeight           = errors.New("gomwan: WANs weight is 0")
	ErrWansWeightLarge      = errors.New("gomwan: WANs weight is larger than 1")
	ErrNoMustBeReachableIps = errors.New("gomwan: no must be reachable IPs found")
	ErrDestinationIps       = errors.New("gomwan: no destination IPs found")
	ErrSourceIps            = errors.New("gomwan: no source IPs found")
	ErrDestinationSourceIps = errors.New("gomwan: destination IPs or source IPs must be provided")
)
