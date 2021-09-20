// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	"fmt"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ========================== //
// == eBPF Code Generation == //
// ========================== //

func generateCodeBlock(auditEvent tp.AuditEventType) (string, error) {
	// not implemented yet
	return "// code block ***\n", nil
}

func (ea *EventAuditor) GenerateCodeBlock(auditEvent tp.AuditEventType) (string, error) {
	var err error
	var ok bool
	var codeBlock string

	ea.CacheIndexLock.Lock()
	defer ea.CacheIndexLock.Unlock()

	// -- remove --
	ea.Logger.Printf("Generating code block from: %v", auditEvent)
	// -- remove --

	eventStr := fmt.Sprintf("%v", auditEvent)
	if codeBlock, ok = ea.EventCodeBlockCache[eventStr]; ok {
		return codeBlock, nil

	} else if codeBlock, err = generateCodeBlock(auditEvent); err != nil {
		return "", err
	}

	ea.EventCodeBlockCache[eventStr] = codeBlock
	return codeBlock, nil
}

func (ea *EventAuditor) GenerateAuditProgram(probe string, codeBlocks []string) string {
	// not implemented yet
	s := fmt.Sprintf("// source (%v) ***\n%v// source ***\n", probe, codeBlocks)
	return s
}

func (ea *EventAuditor) LoadAuditProgram(source string) (uint32, error) {
	ea.CacheIndexLock.Lock()
	defer ea.CacheIndexLock.Unlock()

	// -- remove --
	ea.Logger.Printf("Generating audit program from: %v", source)
	// -- remove --

	index := ea.NextJumpTableIndex
	if jumpTableIndex, ok := ea.EventProgramCache[source]; ok {
		return jumpTableIndex, nil
	}

	// TODO:
	// build the source
	// load the bytecode
	// set ka_event_jump_table[index] = progfd
	// ea.EventProgramCache[source] = index

	ea.NextJumpTableIndex += 1
	return index, nil
}
