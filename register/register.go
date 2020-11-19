package register

import (
	"github.com/bitxhub/bitxid"
	"github.com/meshplus/bitxhub-core/agency"
	"github.com/meshplus/bitxhub-kit/storage"
	"github.com/sirupsen/logrus"
)

func NewMethodRegistryRegister(ts storage.Storage, ds storage.Storage, l logrus.FieldLogger) agency.Registry {
	r, err := bitxid.NewMethodRegistry(ts, ds, l)
	if err != nil {
		return nil
	}
	return r
}

func NewDIDRegistryRegister(ts storage.Storage, ds storage.Storage, l logrus.FieldLogger) agency.Registry {
	r, err := bitxid.NewMethodRegistry(ts, ds, l)
	if err != nil {
		return nil
	}
	return r
}

func init() {
	agency.RegisterRegistryConstructor("method", NewMethodRegistryRegister)
	agency.RegisterRegistryConstructor("did", NewDIDRegistryRegister)
}
