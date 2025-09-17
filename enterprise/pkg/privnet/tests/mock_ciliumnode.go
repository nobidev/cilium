package tests

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
)

const nodeName = "foobar-worker-1"
const nodeUID = k8stypes.UID("a354cce5-e6dc-4cb1-8125-a3a1bf93fd8a")

func mockLocalCiliumNodeCell(t testing.TB) cell.Cell {
	t.Helper()

	return cell.Group(
		cell.Invoke(createLocalCiliumNode),
	)
}

func createLocalCiliumNode(cs client.Clientset) error {
	_, err := cs.CiliumV2().CiliumNodes().Create(
		context.Background(),
		&cilium_v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
				UID:  nodeUID,
			},
		},
		metav1.CreateOptions{},
	)
	return err
}
