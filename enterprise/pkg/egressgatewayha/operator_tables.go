package egressgatewayha

import (
	"fmt"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/apimachinery/pkg/types"
)

func (p *PolicyConfig) Key() index.Key {
	return index.Key(p.id.String())
}

var (
	OperatorIndex = statedb.Index[*PolicyConfig, types.NamespacedName]{
		Name: "byID",
		FromObject: func(s *PolicyConfig) index.KeySet {
			return index.NewKeySet(s.Key())
		},
		FromKey: func(key types.NamespacedName) index.Key {
			return index.Key(key.String())
		},
		FromString: index.FromString,
		Unique:     true,
	}
)

func (p *PolicyConfig) TableHeader() []string {
	return []string{"ID", "Generation", "Statuses"}
}

// TableRow prints out a policy config as a row of a table.
// Because this type is large, we emit mostly fields that
// are not part of the original policy spec, such as status.
// Full dumps can use json output.
func (p *PolicyConfig) TableRow() []string {
	ss := []string{}
	for _, status := range p.groupStatuses {
		gs := fmt.Sprintf("active=%v", status.activeGatewayIPs)
		if p.azAffinity != azAffinityDisabled {
			gs += fmt.Sprintf(",activeByAZ=%v", status.activeGatewayIPsByAZ)
		}
		gs += fmt.Sprintf(",healthy=%v", status.healthyGatewayIPs)
		if len(status.egressIPByGatewayIP) != 0 {
			gs += fmt.Sprintf(",byGateway=%v", status.egressIPByGatewayIP)
		}
		ss = append(ss, gs)
	}
	return []string{
		strings.TrimPrefix(p.id.String(), "/"),
		fmt.Sprintf("%d", p.generation),
		fmt.Sprintf("%v", ss),
	}
}

func newOperatorTables(db *statedb.DB) (statedb.RWTable[*PolicyConfig], error) {
	statusTable, err := statedb.NewTable("policy-config", OperatorIndex)
	if err != nil {
		return nil, err
	}
	if err := db.RegisterTable(statusTable); err != nil {
		return nil, err
	}
	return statusTable, nil
}
