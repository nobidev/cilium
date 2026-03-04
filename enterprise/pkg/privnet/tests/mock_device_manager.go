// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tests

import (
	"fmt"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/linux/device"
	"github.com/cilium/cilium/pkg/time"
)

func mockDeviceManagerCell(t testing.TB) cell.Cell {
	t.Helper()

	return cell.Group(
		cell.ProvidePrivate(
			newManagedDevicesTable,
		),
		cell.Provide(
			func(db *statedb.DB, table statedb.RWTable[*device.DesiredDevice]) device.ManagerOperations {
				return &mockDeviceManager{
					db:     db,
					table:  table,
					owners: sets.New[device.DeviceOwner](),
				}
			},
		),
	)
}

type mockDeviceManager struct {
	db     *statedb.DB
	table  statedb.RWTable[*device.DesiredDevice]
	owners sets.Set[device.DeviceOwner]
}

func (m *mockDeviceManager) UpsertDevice(device device.DesiredDevice) error {
	if !m.owners.Has(device.Owner) {
		return fmt.Errorf("owner %s not registered", device.Owner.Name)
	}

	wtx := m.db.WriteTxn(m.table)
	defer wtx.Abort()

	_, _, err := m.table.Insert(wtx, &device)
	if err != nil {
		return err
	}

	wtx.Commit()
	return nil
}

func (m *mockDeviceManager) UpsertDeviceWait(device device.DesiredDevice, timeout time.Duration) error {
	return m.UpsertDevice(device)
}

func (m *mockDeviceManager) DeleteDevice(device device.DesiredDevice) error {
	if !m.owners.Has(device.Owner) {
		return fmt.Errorf("owner %s not registered", device.Owner.Name)
	}

	wtx := m.db.WriteTxn(m.table)
	defer wtx.Abort()

	_, _, err := m.table.Delete(wtx, &device)
	if err != nil {
		return err
	}

	wtx.Commit()
	return nil
}

func (m *mockDeviceManager) GetOrRegisterOwner(name string) device.DeviceOwner {
	req := device.DeviceOwner{Name: name}
	m.owners.Insert(req)
	return req
}

func (m *mockDeviceManager) RemoveOwner(owner device.DeviceOwner) error {
	m.owners.Delete(owner)
	return nil
}

func (m *mockDeviceManager) RegisterInitializer(name string) device.Initializer {
	return device.Initializer{}
}

func (m *mockDeviceManager) FinalizeInitializer(initializer device.Initializer) {
	// TODO: hardening tasks.
	// Need to add tests for devices initializers.
}

func newManagedDevicesTable(db *statedb.DB) (statedb.RWTable[*device.DesiredDevice], error) {
	return statedb.NewTable(
		db,
		"test-privnet-desired-devices",
		device.DesiredDeviceIndex,
		device.DesiredDeviceNameIndex,
	)
}
