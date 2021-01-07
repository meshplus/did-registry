package contracts

import (
	"encoding/json"

	"github.com/bitxhub/bitxid"
	"github.com/bitxhub/did-method-registry/converter"
	"github.com/meshplus/bitxhub-core/agency"
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/treasersimplifies/cstr"
)

// DIDInfo is used for return struct.
type DIDInfo struct {
	DID     string        // did name
	DocAddr string        // address where the doc file stored
	DocHash []byte        // hash of the doc file
	Doc     bitxid.DIDDoc // doc content
	Status  string        // status of did
}

// DIDRegistry represents all things of did registry.
// @SelfID: self Method ID
// @ChildIDs: Method IDs of the child chain
type DIDRegistry struct {
	boltvm.Stub
	Registry   *bitxid.DIDRegistry
	Initalized bool
	SelfID     bitxid.DID
	ParentID   bitxid.DID // not used
	ChildIDs   []bitxid.DID
}

// NewDIDRegistry .
func NewDIDRegistry() agency.Contract {
	return &DIDRegistry{}
}

func init() {
	agency.RegisterContractConstructor("did registry", constant.DIDRegistryContractAddr.Address(), NewDIDRegistry)
}

// Init sets up the whole registry,
// caller should be admin.
func (dr *DIDRegistry) Init(caller string) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if dr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dr.Caller(), caller))
	}

	if dr.Initalized {
		return boltvm.Error("init err, already init")
	}
	s := converter.StubToStorage(dr.Stub)
	r, err := bitxid.NewDIDRegistry(s, dr.Logger(), bitxid.WithDIDAdmin(bitxid.DID(caller)))
	if err != nil {
		return boltvm.Error("init err, " + err.Error())
	}
	dr.Registry = r
	err = dr.Registry.SetupGenesis()
	if err != nil {
		return boltvm.Error("init genesis err, " + err.Error())
	}
	dr.SelfID = dr.Registry.GetSelfID()
	dr.Initalized = true

	dr.Logger().Info(cstr.Dye("DID Registry init success v1 !", "Green"))
	return boltvm.Success(nil)
}

// GetMethodID gets method id of the registry.
func (dr *DIDRegistry) GetMethodID() *boltvm.Response {
	return boltvm.Success([]byte(dr.SelfID))
}

// SetMethodID sets method id of did registtry,
// caller should be admin.
func (dr *DIDRegistry) SetMethodID(caller, method string) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if dr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dr.Caller(), caller))
	}
	if !dr.Registry.HasAdmin(callerDID) {
		return boltvm.Error("caller has no authorization.")
	}
	dr.SelfID = bitxid.DID(method)
	return boltvm.Success(nil)
}

// Register anchors infomation for the did.
func (dr *DIDRegistry) Register(caller string, docAddr string, docHash []byte, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if dr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dr.Caller(), caller))
	}
	if dr.SelfID != bitxid.DID(callerDID.GetMethod()) {
		return boltvm.Error(didNotOnThisChainError(string(callerDID), string(dr.SelfID)))
	}

	docAddr, docHash, err := dr.Registry.Register(bitxid.DocOption{
		ID:   bitxid.DID(callerDID),
		Addr: docAddr,
		Hash: docHash,
	})
	if err != nil {
		return boltvm.Error(err.Error())
	}

	return boltvm.Success(nil)
}

// Update updates did infomation.
func (dr *DIDRegistry) Update(caller string, docAddr string, docHash []byte, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if dr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dr.Caller(), caller))
	}
	if dr.SelfID != bitxid.DID(callerDID.GetMethod()) {
		return boltvm.Error(didNotOnThisChainError(string(callerDID), string(dr.SelfID)))
	}

	docAddr, docHash, err := dr.Registry.Update(bitxid.DocOption{
		ID:   bitxid.DID(callerDID),
		Addr: docAddr,
		Hash: docHash,
	})
	if err != nil {
		return boltvm.Error(err.Error())
	}

	return boltvm.Success(nil)
}

// Resolve gets all infomation of the did.
func (dr *DIDRegistry) Resolve(caller string) *boltvm.Response {
	callerDID := bitxid.DID(caller)

	item, _, exist, err := dr.Registry.Resolve(callerDID)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	if !exist {
		return boltvm.Error("Not found")
	}
	didInfo := DIDInfo{
		DID:     string(item.ID),
		DocAddr: item.DocAddr,
		DocHash: item.DocHash,
		Status:  string(item.Status),
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
		return boltvm.Error("caller has no authorization.")
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
		return boltvm.Error("caller has no authorization.")
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
		return boltvm.Error("caller has no authorization.")
	}

	err := dr.Registry.Delete(callerDID)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}

// HasAdmin querys whether caller is an admin of the registry.
func (dr *DIDRegistry) HasAdmin(caller string) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if dr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dr.Caller(), caller))
	}

	res := dr.Registry.HasAdmin(callerDID)
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
		return boltvm.Error("caller has no authorization.")
	}

	err := dr.Registry.AddAdmin(bitxid.DID(adminToAdd))
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}

func docIDNotMatchDidError(c1 string, c2 string) string {
	return "doc ID(" + c1 + ") not match the did(" + c2 + ")"
}

func didNotOnThisChainError(did string, method string) string {
	return "DID(" + did + ") not on the chain(" + method + ")"
}
