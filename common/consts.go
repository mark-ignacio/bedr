package common

// SpecVersion sets expections going forward for comms
type SpecVersion uint8

// OpCode is an enum for opcodes that split out checkin
type OpCode uint8

const (
	// SpecDC27 is what @mark-ignacio presented at DC27
	SpecDC27 SpecVersion = iota + 1
)

// Contains (hopefully) self-explanatory opcodes that bedr communicates
const (
	OpHeartbeat OpCode = iota + 1
	OpMachineFacts
	OpEvents
	OpWhoDis
)
