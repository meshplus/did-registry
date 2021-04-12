package contracts

import (
	"fmt"

	"github.com/meshplus/bitxhub-core/agency"
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxid"
	"github.com/meshplus/did-registry/converter"
)

const (
	VCRegistryKey = "VCRegistryKey"
	adminVCKey    = "admin-vc"
)

// NewVCManager .
func NewVCManager() agency.Contract {
	return &VCManager{}
}

func init() {
	agency.RegisterContractConstructor("vc registry", constant.VCRegistryContractAddr.Address(), NewVCManager)
}

// VCManager presents verifiable credential registry
type VCManager struct {
	boltvm.Stub
}

// VCRegistry represents all things of vc registry.
// @SelfID: self Method ID
// @ChildIDs: Method IDs of the child chain
type VCRegistry struct {
	Initalized bool
	Registry   *bitxid.VCRegistry
}

func (vm *VCManager) getVCRegistry() *VCRegistry {
	vr := &VCRegistry{}
	vm.GetObject(VCRegistryKey, &vr)
	if vr.Registry != nil {
		vr.loadStore(vm.Stub)
	}
	return vr
}

// if you need to use registry store, you have to manully load it,
// returns err if registry is nil
func (vr *VCRegistry) loadStore(stub boltvm.Stub) error {
	if vr.Registry == nil {
		return fmt.Errorf("registry is nil")
	}
	vr.Registry.Store = converter.StubToStorage(stub)
	return nil
}

func (mm *VCManager) Init() *boltvm.Response { // caller string
	vcr := mm.getVCRegistry()

	// var admin string
	// mm.GetObject(adminVCKey, &admin)
	// mm.Logger().Info("admin get: " + string(admin))

	if vcr.Initalized {
		return boltvm.Error("init err, already init")
	}

	s := converter.StubToStorage(mm.Stub)
	r, err := bitxid.NewVCRegistry(s)
	if err != nil {
		return boltvm.Error("init err, " + err.Error())
	}
	vcr.Registry = r
	vcr.Initalized = true

	mm.SetObject(VCRegistryKey, vcr)
	mm.Logger().Info("vc init success 2")

	return boltvm.Success(nil)
}

func (mm *VCManager) CreateClaimTyp(ctb []byte) *boltvm.Response {
	mm.Logger().Info("vc in CreateClaimTyp")
	vcr := mm.getVCRegistry()

	if !vcr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	ct := &bitxid.ClaimTyp{}
	err := ct.Unmarshal(ctb)
	if err != nil {
		return boltvm.Error("params unmarshal err: " + err.Error())
	}

	ctid, err := vcr.Registry.CreateClaimTyp(ct)
	if err != nil {
		return boltvm.Error("create claim type err, " + err.Error())
	}
	mm.SetObject(VCRegistryKey, vcr)

	return boltvm.Success([]byte(ctid))
}

func (mm *VCManager) GetClaimTyp(ctid string) *boltvm.Response {
	mm.Logger().Info("vc in GetClaimTyp")
	vcr := mm.getVCRegistry()

	if !vcr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	ct, err := vcr.Registry.GetClaimTyp(ctid)
	if err != nil {
		return boltvm.Error("get claim type err, " + err.Error())
	}

	mm.Logger().Info("vc get: ", ct)

	b, err := ct.Marshal()
	if err != nil {
		return boltvm.Error("claim unmarshal err, " + err.Error())
	}

	return boltvm.Success(b)
}

func (mm *VCManager) GetAllClaimTyps() *boltvm.Response {
	mm.Logger().Info("vc in GetAllClaimTyps")
	vcr := mm.getVCRegistry()

	if !vcr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	ctlist, err := vcr.Registry.GetAllClaimTyps()
	if err != nil {
		return boltvm.Error("get all claim types err: " + err.Error())
	}

	b, err := bitxid.Marshal(ctlist)
	if err != nil {
		return boltvm.Error("marshal ctlist err: " + err.Error())
	}

	return boltvm.Success(b)
}

// // this function should not exist
// func (mm *VCManager) DeleteClaimtyp(ctid string) *boltvm.Response {
// 	vcr := mm.getVCRegistry()

// 	if !vcr.Initalized {
// 		return boltvm.Error("Registry not initialized")
// 	}

// 	vcr.Registry.DeleteClaimtyp(ctid)
// 	return boltvm.Success(nil)
// }

func (mm *VCManager) StoreVC(cb []byte) *boltvm.Response {
	vcr := mm.getVCRegistry()

	if !vcr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	c := &bitxid.Credential{}
	err := c.Unmarshal(cb)
	if err != nil {
		return boltvm.Error("params unmarshal err: " + err.Error())
	}

	cid, err := vcr.Registry.StoreVC(c)
	if err != nil {
		return boltvm.Error("store vc err: " + err.Error())
	}
	return boltvm.Success([]byte(cid))
}

func (mm *VCManager) GetVC(cid string) *boltvm.Response {
	vcr := mm.getVCRegistry()

	if !vcr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	c, err := vcr.Registry.GetVC(cid)
	if err != nil {
		return boltvm.Error("get vc err: " + err.Error())
	}

	b, err := c.Marshal()
	if err != nil {
		return boltvm.Error("credential unmarshal err, " + err.Error())
	}

	return boltvm.Success(b)
}

func (mm *VCManager) DeleteVC(caller, cid string) *boltvm.Response {
	vcr := mm.getVCRegistry()

	if !vcr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	vc, err := vcr.Registry.GetVC(cid)
	if err != nil {
		return boltvm.Error("get vc err, " + err.Error())
	}

	callerDID := bitxid.DID(caller)
	if callerDID != vc.Issuer {
		return boltvm.Error("delete vc err, caller(" + string(callerDID) + ") is not issuer(" + string(vc.Issuer) + ")")
	}

	vcr.Registry.DeleteVC(cid)

	return boltvm.Success(nil)
}
