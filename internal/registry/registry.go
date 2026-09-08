package registry

import (
	"fmt"

	"github.com/khulnasoft-lab/vuln-list-update/internal/source"
	"github.com/khulnasoft-lab/vuln-list-update/kevc"
	"github.com/khulnasoft-lab/vuln-list-update/nvd"
	"github.com/khulnasoft-lab/vuln-list-update/osv"
)

func Canonical(name string) (source.Adapter, error) {
	switch name {
	case "nvd-canonical":
		return nvd.NewAdapter(nil), nil
	case "kevc-canonical":
		return kevc.NewAdapter(), nil
	case "osv-canonical":
		return osv.NewAdapter(), nil
	default:
		return nil, fmt.Errorf("unknown canonical source %q", name)
	}
}