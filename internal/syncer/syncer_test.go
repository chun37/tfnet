package syncer

import (
	"reflect"
	"testing"

	"tfnet/internal/ledger"
)

func TestDiffMembers(t *testing.T) {
	mk := func(ids ...string) *ledger.State {
		s := ledger.NewState()
		for _, id := range ids {
			s.Members[id] = ledger.Subject{NodeID: id}
		}
		return s
	}
	cases := []struct {
		name    string
		before  *ledger.State
		after   *ledger.State
		added   []string
		removed []string
	}{
		{"nil before -> some after", nil, mk("a", "b"), []string{"a", "b"}, nil},
		{"same set", mk("a", "b"), mk("b", "a"), nil, nil},
		{"add one", mk("a"), mk("a", "b"), []string{"b"}, nil},
		{"remove one", mk("a", "b"), mk("b"), nil, []string{"a"}},
		{"swap", mk("a", "b"), mk("b", "c"), []string{"c"}, []string{"a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, r := diffMembers(tc.before, tc.after)
			if !reflect.DeepEqual(a, tc.added) {
				t.Errorf("added: got %v want %v", a, tc.added)
			}
			if !reflect.DeepEqual(r, tc.removed) {
				t.Errorf("removed: got %v want %v", r, tc.removed)
			}
		})
	}
}
