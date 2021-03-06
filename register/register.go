package register

import (
	"github.com/meshplus/bitxhub-core/agency"
	"github.com/meshplus/bitxhub-kit/storage"
	"github.com/meshplus/bitxid"
	"github.com/sirupsen/logrus"
)

func NewMethodRegistryRegister(ts storage.Storage, l logrus.FieldLogger) agency.Registry {
	r, err := bitxid.NewChainDIDRegistry(ts, l)
	// TODO WithAdmin
	if err != nil {
		return nil
	}
	return r
}

func NewDIDRegistryRegister(ts storage.Storage, l logrus.FieldLogger) agency.Registry {
	r, err := bitxid.NewAccountDIDRegistry(ts, l)
	if err != nil {
		return nil
	}
	return r
}

// func NewVCRegistryRegister(ts storage.Storage) agency.Registry {
// 	r, err := bitxid.NewAccountDIDRegistry(ts, l)
// 	if err != nil {
// 		return nil
// 	}
// 	return r
// }

func init() {
	agency.RegisterRegistryConstructor("chain-did", NewMethodRegistryRegister)
	agency.RegisterRegistryConstructor("account-did", NewDIDRegistryRegister)
	// agency.RegisterRegistryConstructor("vc", NewDIDRegistryRegister)
}
