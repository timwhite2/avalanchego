// Copyright (C) 2019-2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ava-labs/avalanchego/vms/components/avax (interfaces: TransferableOut)

// Package avax is a generated GoMock package.
package avax

import (
	reflect "reflect"

	snow "github.com/ava-labs/avalanchego/snow"
	gomock "github.com/golang/mock/gomock"
)

// MockTransferableOut is a mock of TransferableOut interface.
type MockTransferableOut struct {
	ctrl     *gomock.Controller
	recorder *MockTransferableOutMockRecorder
}

// MockTransferableOutMockRecorder is the mock recorder for MockTransferableOut.
type MockTransferableOutMockRecorder struct {
	mock *MockTransferableOut
}

// NewMockTransferableOut creates a new mock instance.
func NewMockTransferableOut(ctrl *gomock.Controller) *MockTransferableOut {
	mock := &MockTransferableOut{ctrl: ctrl}
	mock.recorder = &MockTransferableOutMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTransferableOut) EXPECT() *MockTransferableOutMockRecorder {
	return m.recorder
}

// Amount mocks base method.
func (m *MockTransferableOut) Amount() uint64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Amount")
	ret0, _ := ret[0].(uint64)
	return ret0
}

// Amount indicates an expected call of Amount.
func (mr *MockTransferableOutMockRecorder) Amount() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Amount", reflect.TypeOf((*MockTransferableOut)(nil).Amount))
}

// InitCtx mocks base method.
func (m *MockTransferableOut) InitCtx(arg0 *snow.Context) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "InitCtx", arg0)
}

// InitCtx indicates an expected call of InitCtx.
func (mr *MockTransferableOutMockRecorder) InitCtx(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitCtx", reflect.TypeOf((*MockTransferableOut)(nil).InitCtx), arg0)
}

// Verify mocks base method.
func (m *MockTransferableOut) Verify() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify")
	ret0, _ := ret[0].(error)
	return ret0
}

// Verify indicates an expected call of Verify.
func (mr *MockTransferableOutMockRecorder) Verify() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockTransferableOut)(nil).Verify))
}

// VerifyState mocks base method.
func (m *MockTransferableOut) VerifyState() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyState")
	ret0, _ := ret[0].(error)
	return ret0
}

// VerifyState indicates an expected call of VerifyState.
func (mr *MockTransferableOutMockRecorder) VerifyState() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyState", reflect.TypeOf((*MockTransferableOut)(nil).VerifyState))
}
