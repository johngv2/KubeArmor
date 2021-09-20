// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	"math/rand"
	"sync"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"

	lbpf "github.com/kubearmor/libbpf"
)

// =================== //
// == Event Auditor == //
// =================== //

// EventAuditor Structure
type EventAuditor struct {
	// logs
	Logger *fd.Feeder

	// bpf
	BPFManager *KABPFManager

	// all entrypoints that KubeArmor supports
	SupportedEntryPoints []string

	// all entrypoints in the audit policy
	ActiveEntryPoints []string

	// entrypoint bpf
	EntryPointBPF *lbpf.KABPFObject

	// cache for event code blocks
	// map[eventString]codeBlock
	EventCodeBlockCache map[string]string

	// cache for loaded programs
	// map[sourceCode]jumpTableIndex
	EventProgramCache map[string]uint32

	// next index to use
	NextJumpTableIndex uint32

	// lock for caches and index count
	CacheIndexLock *sync.RWMutex
}

// NewEventAuditor Function
func NewEventAuditor(feeder *fd.Feeder) *EventAuditor {
	ea := new(EventAuditor)

	ea.Logger = feeder

	// initialize ebpf manager
	ea.BPFManager = NewKABPFManager()

	// initialize caches
	ea.EventCodeBlockCache = make(map[string]string)
	ea.EventProgramCache = make(map[string]uint32)

	ea.NextJumpTableIndex = 0
	ea.CacheIndexLock = new(sync.RWMutex)

	if err := ea.BPFManager.SetObjsMapsPath("./BPF/objs"); err != nil {
		ea.Logger.Errf("Failed to set ebpf maps path: %v", err)
		return nil
	}

	if err := ea.BPFManager.SetObjsProgsPath("./BPF/objs"); err != nil {
		ea.Logger.Errf("Failed to set ebpf programs path: %v", err)
		return nil
	}

	if err := ea.InitializeProcessMaps(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to initialize process maps: %v", err)
		return nil
	}

	if err := ea.InitializeProcessPrograms(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to initialize process programs: %v", err)
		goto fail1
	}

	// initialize entrypoints
	if !ea.InitializeEntryPoints() {
		ea.Logger.Err("Failed to initialize entrypoints")
		goto fail2
	}

	return ea

fail2:
	// destroy process programs
	_ = ea.DestroyProcessPrograms(ea.BPFManager)
fail1:
	// destroy process maps
	_ = ea.DestroyProcessMaps(ea.BPFManager)

	return nil
}

// DestroyEventAuditor Function
func (ea *EventAuditor) DestroyEventAuditor() error {
	// destroy entrypoints
	if !ea.DestroyEntryPoints() {
		ea.Logger.Err("Failed to destroy entrypoints")
	}

	// destroy process programs
	err1 := ea.DestroyProcessPrograms(ea.BPFManager)
	if err1 != nil {
		ea.Logger.Errf("Failed to destroy process programs: %v", err1)
	}

	// destroy process maps
	err2 := ea.DestroyProcessMaps(ea.BPFManager)
	if err2 != nil {
		ea.Logger.Errf("Failed to destroy process maps: %v", err2)
	}

	ea.BPFManager = nil
	ea.Logger = nil

	return AppendErrors(err1, err2)
}

// ============================= //
// == Audit Policy Management == //
// ============================= //

func GetEventId(probe string) uint32 {
	// not implemented yet
	return uint32(rand.Intn(30))
}

func (ea *EventAuditor) UpdateAuditPrograms(endPoints []tp.EndPoint, endPointsLock *sync.RWMutex, containers map[string]tp.Container) {
	endPointsLock.Lock()
	defer endPointsLock.Unlock()

	for _, ep := range endPoints {
		progCodeBlocks := make(map[string][]string)
		progLoaded := make(map[uint32]uint32)

		if len(ep.AuditPolicies) == 0 {
			continue
		}

		// generate the event code blocks
		for _, auditPolicy := range ep.AuditPolicies {
			for _, eventRule := range auditPolicy.Events {
				if codeBlock, err := ea.GenerateCodeBlock(eventRule); err == nil {
					if !kl.ContainsElement(progCodeBlocks[eventRule.Probe], codeBlock) {
						current := progCodeBlocks[eventRule.Probe]
						progCodeBlocks[eventRule.Probe] = append(current, codeBlock)
					}
				} else {
					ea.Logger.Printf("Failed to generate event code block: %v", err)
				}
			}
		}

		ea.Logger.Printf("progCodeBlocks %v", progCodeBlocks)

		// generate and load the event programs
		for probe, codeBlocks := range progCodeBlocks {
			source := ea.GenerateAuditProgram(probe, codeBlocks)
			eventId := GetEventId(probe)

			if index, err := ea.LoadAuditProgram(source); err == nil {
				progLoaded[eventId] = index
			} else {
				ea.Logger.Printf("Failed to load audit program: %v", err)
			}
		}

		ea.Logger.Printf("progLoaded %v", progLoaded)

		// set index on event filter map
		for _, containerName := range ep.Containers {
			pidns := containers[containerName].PidNS
			mntns := containers[containerName].MntNS

			for eventId, jmpTableIndex := range progLoaded {
				ea.Logger.Printf("pidns=%v, mntns=%v, eventId=%v, jumpidx=%v",
					pidns, mntns, eventId, jmpTableIndex)
				// TODO: event_filter_map[key] = value
				/*
					struct event_filter_key {
						__u32 pid_ns;
						__u32 mnt_ns;
						__u32 event_id;
					};

					struct event_filter_value {
						__u32 jmp_idx;
					};
				*/
			}
		}
	}
}
