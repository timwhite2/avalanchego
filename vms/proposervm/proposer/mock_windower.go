// Copyright (C) 2019-2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ava-labs/avalanchego/vms/proposervm/proposer (interfaces: Windower)

// Package proposer is a generated GoMock package.
package proposer

import (
	context "context"
	reflect "reflect"
	time "time"

	ids "github.com/ava-labs/avalanchego/ids"
	validators "github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	gomock "github.com/golang/mock/gomock"
)

// MockWindower is a mock of Windower interface.
type MockWindower struct {
	ctrl     *gomock.Controller
	recorder *MockWindowerMockRecorder
}

// MockWindowerMockRecorder is the mock recorder for MockWindower.
type MockWindowerMockRecorder struct {
	mock *MockWindower
}

// NewMockWindower creates a new mock instance.
func NewMockWindower(ctrl *gomock.Controller) *MockWindower {
	mock := &MockWindower{ctrl: ctrl}
	mock.recorder = &MockWindowerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWindower) EXPECT() *MockWindowerMockRecorder {
	return m.recorder
}

// DelayAndBlsKey mocks base method.
func (m *MockWindower) DelayAndBlsKey(arg0 context.Context, arg1, arg2 uint64, arg3 ids.NodeID) (time.Duration, *bls.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DelayAndBlsKey", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(time.Duration)
	ret1, _ := ret[1].(*bls.PublicKey)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// DelayAndBlsKey indicates an expected call of DelayAndBlsKey.
func (mr *MockWindowerMockRecorder) DelayAndBlsKey(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DelayAndBlsKey", reflect.TypeOf((*MockWindower)(nil).DelayAndBlsKey), arg0, arg1, arg2, arg3)
}

// Proposers mocks base method.
func (m *MockWindower) Proposers(arg0 context.Context, arg1, arg2 uint64) ([]*validators.GetValidatorOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Proposers", arg0, arg1, arg2)
	ret0, _ := ret[0].([]*validators.GetValidatorOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Proposers indicates an expected call of Proposers.
func (mr *MockWindowerMockRecorder) Proposers(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Proposers", reflect.TypeOf((*MockWindower)(nil).Proposers), arg0, arg1, arg2)
}
