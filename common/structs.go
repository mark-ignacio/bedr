package common

// SupMessage is your usual overloaded agent checkin event
type SupMessage struct {
	Op       OpCode
	Spec     SpecVersion `json:"s"`
	Syscalls []Syscall   `json:",omitempty"`
	Error    string      `json:",omitempty"`
	Facts    *HostFacts
}

// SupReply is essentially a polling mechanism

// Syscall is an abstraction of a syscall event
type Syscall struct {
	Timestamp uint64 `json:"ts"`
	Nr        uint64
	PID       uint32

	// execve stuff
	PPID uint32   `json:",omitempty"`
	Exe  string   `json:",omitempty"`
	Args []string `json:",omitempty"`

	// connect() + bind() stuff
	Host string `json:",omitempty"`
	Port uint32 `json:",omitempty"`
}

// HostFacts are self-reported facts about the hosts. For usability's sake.
type HostFacts struct {
	Hostname string
}
