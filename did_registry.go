package contracts

import (
	"encoding/json"
	"path/filepath"

	"github.com/bitxhub/bitxid"
	"github.com/meshplus/bitxhub-core/agency"
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub-kit/storage/leveldb"
	"github.com/meshplus/bitxhub-model/constant"
)

// DIDInfo is used for return struct.
type DIDInfo struct {
	DID     string        // did name
	DocAddr string        // address where the doc file stored
	DocHash []byte        // hash of the doc file
	Doc     bitxid.DIDDoc // doc content
	Status  int           // status of did
}

// DIDRegistry represents all things of did registry.
type DIDRegistry struct {
	boltvm.Stub
	Registry   *bitxid.DIDRegistry
	Initalized bool
}

// NewDIDRegistry .
func NewDIDRegistry() agency.Contract {
	return &DIDRegistry{}
}

func init() {
	agency.RegisterContractConstructor("method registry", constant.DIDRegistryContractAddr.Address(), NewDIDRegistry)
}

// Init sets up the whole registry,
// caller should be admin.
func (dr *DIDRegistry) Init(caller string) *boltvm.Response {
	if dr.Initalized {
		boltvm.Error("did registry already initalized")
	}

	callerDID := bitxid.DID(caller)
	if dr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dr.Caller(), caller))
	}

	ts, err := leveldb.New(filepath.Join(repoRoot, "storage", "DIDRegistry"))
	if err != nil {
		return boltvm.Error("new store: " + err.Error())
	}
	l := dr.Logger()                          // to be removed
	conf, err := bitxid.DefaultBitXIDConfig() // to be changed
	if err != nil {
		return boltvm.Error(err.Error())
	}

	r, err := bitxid.NewDIDRegistry(ts, ts, l, &conf.DIDConfig)
	if err != nil {
		return boltvm.Error(err.Error())
	}

	err = r.SetupGenesis()
	if err != nil {
		return boltvm.Error(err.Error())
	}

	dr.Registry = r
	dr.Initalized = true
	return boltvm.Success(nil)
}

// Register anchors infomation for the did.
func (dr *DIDRegistry) Register(caller string, didDoc *bitxid.DIDDoc, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if !callerDID.IsValidFormat() {
		return boltvm.Error("not valid did format")
	}
	if dr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dr.Caller(), caller))
	}
	// sig .
	docAddr, docHash, err := dr.Registry.Register(didDoc)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	didInfo := DIDInfo{
		DID:     caller,
		DocAddr: docAddr,
		DocHash: docHash,
	}
	b, err := bitxid.Struct2Bytes(didInfo)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(b)
}

// Update updates did infomation.
func (dr *DIDRegistry) Update(caller string, didDoc *bitxid.DIDDoc, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if dr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dr.Caller(), caller))
	}
	docAddr, docHash, err := dr.Registry.Update(didDoc)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	didInfo := DIDInfo{
		DID:     caller,
		DocAddr: docAddr,
		DocHash: docHash,
	}
	b, err := bitxid.Struct2Bytes(didInfo)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(b)
}

// Resolve gets all infomation of the did.
func (dr *DIDRegistry) Resolve(caller string, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if dr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dr.Caller(), caller))
	}
	item, doc, err := dr.Registry.Resolve(callerDID)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	didInfo := DIDInfo{
		DID:     caller,
		DocAddr: item.DocAddr,
		DocHash: item.DocHash,
		Doc:     *doc,
		Status:  int(item.Status),
	}
	b, err := bitxid.Struct2Bytes(didInfo)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(b)
}

// Freeze freezes the did in this registry,
// caller should be admin.
func (dr *DIDRegistry) Freeze(caller string, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if dr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dr.Caller(), caller))
	}
	if !dr.Registry.HasAdmin(callerDID) {
		boltvm.Error("caller has no authorization.")
	}
	err := dr.Registry.Freeze(callerDID)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}

// UnFreeze unfreezes the did in the registry,
// caller should be admin.
func (dr *DIDRegistry) UnFreeze(caller string, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if dr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dr.Caller(), caller))
	}
	if !dr.Registry.HasAdmin(callerDID) {
		boltvm.Error("caller has no authorization.")
	}
	err := dr.Registry.UnFreeze(callerDID)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}

// Delete deletes the did,
// caller should be admin.
func (dr *DIDRegistry) Delete(caller string, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if dr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dr.Caller(), caller))
	}
	if !dr.Registry.HasAdmin(callerDID) {
		boltvm.Error("caller has no authorization.")
	}
	err := dr.Registry.Delete(callerDID)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}

// HasAdmin querys whether caller is an admin of the registry.
func (dr *DIDRegistry) HasAdmin(caller string) *boltvm.Response {
	res := dr.Registry.HasAdmin(bitxid.DID(caller))
	if res == true {
		return boltvm.Success([]byte("1"))
	}
	return boltvm.Success([]byte("0"))
}

// GetAdmins get admins of the registry.
func (dr *DIDRegistry) GetAdmins() *boltvm.Response {
	admins := dr.Registry.GetAdmins()
	data, err := json.Marshal(admins)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success([]byte(data))
}

// AddAdmin add caller to the admin of the registry,
// caller should be admin.
func (dr *DIDRegistry) AddAdmin(caller string, adminToAdd string) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if dr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dr.Caller(), caller))
	}
	if !dr.Registry.HasAdmin(callerDID) {
		boltvm.Error("caller has no authorization.")
	}

	err := dr.Registry.AddAdmin(bitxid.DID(adminToAdd))
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}
