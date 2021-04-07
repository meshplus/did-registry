package contracts

import (
	"encoding/json"
	"fmt"

	"github.com/meshplus/bitxhub-core/agency"
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxid"
	"github.com/meshplus/did-registry/converter"
)

const (
	AccountDIDRegistryKey = "AccountDIDRegistry"
	adminDIDKey           = "admin-did"
)

// NewAccountDIDManager .
func NewAccountDIDManager() agency.Contract {
	return &AccountDIDManager{}
}

func init() {
	agency.RegisterContractConstructor("account did registry", constant.DIDRegistryContractAddr.Address(), NewAccountDIDManager)
}

// DIDInfo is used for return struct.
type DIDInfo struct {
	DID     string            // did name
	DocAddr string            // address where the doc file stored
	DocHash []byte            // hash of the doc file
	Doc     bitxid.AccountDoc // doc content
	Status  string            // status of did
}

// AccountDIDManager .
type AccountDIDManager struct {
	boltvm.Stub
}

func (dm *AccountDIDManager) getAccountDIDRegistry() *AccountDIDRegistry {
	dr := &AccountDIDRegistry{}
	dm.GetObject(AccountDIDRegistryKey, &dr)
	if dr.Registry != nil {
		dr.loadTable(dm.Stub)
	}
	return dr
}

// AccountDIDRegistry represents all things of did registry.
// @SelfID: self Method ID
// @ChildIDs: Method IDs of the child chain
type AccountDIDRegistry struct {
	// boltvm.Stub
	Registry   *bitxid.AccountDIDRegistry
	Initalized bool
	SelfID     bitxid.DID
	ParentID   bitxid.DID // not used
	ChildIDs   []bitxid.DID
}

// if you need to use registry table, you have to manully load it, so does docdb,
// returns err if registry is nil
func (dr *AccountDIDRegistry) loadTable(stub boltvm.Stub) error {
	if dr.Registry == nil {
		return fmt.Errorf("registry is nil")
	}
	dr.Registry.Table = &bitxid.KVTable{
		Store: converter.StubToStorage(stub),
	}
	return nil
}

// Init sets up the whole registry,
// caller should be admin.
func (dm *AccountDIDManager) Init(caller string) *boltvm.Response {
	dr := dm.getAccountDIDRegistry()

	var admin string
	dm.GetObject(adminDIDKey, &admin)
	dm.Logger().Info("admin get: " + string(admin))

	callerDID := bitxid.DID(caller)
	if dm.Caller() != admin {
		return boltvm.Error("caller (" + dm.Caller() + ") is not admin(" + admin + ")")
	}

	if dm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dm.Caller(), caller))
	}

	if dr.Initalized {
		return boltvm.Error("init err, already init")
	}
	s := converter.StubToStorage(dm.Stub)
	r, err := bitxid.NewAccountDIDRegistry(
		s,
		dm.Logger(),
		bitxid.WithDIDAdmin(callerDID),
		bitxid.WithGenesisAccountDocInfo(
			bitxid.DocInfo{ID: callerDID, Addr: ".", Hash: []byte{}},
		),
	)
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

	dm.SetObject(AccountDIDRegistryKey, dr)
	dm.Logger().Info("DID Registry init success with admin: " + string(callerDID))
	return boltvm.Success(nil)
}

// GetChainDID gets chain did of blockchain which the registry belonging to.
func (dm *AccountDIDManager) GetChainDID() *boltvm.Response {
	dr := dm.getAccountDIDRegistry()

	return boltvm.Success([]byte(dr.SelfID))
}

// SetChainDID sets chain did of the registtry,
// caller should be admin.
func (dm *AccountDIDManager) SetChainDID(caller, chainDID string) *boltvm.Response {
	dr := dm.getAccountDIDRegistry()

	if !dr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)
	if dm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dm.Caller(), caller))
	}
	if !dr.Registry.HasAdmin(callerDID) {
		return boltvm.Error("caller has no permission")
	}
	dr.SelfID = bitxid.DID(chainDID)

	dm.SetObject(AccountDIDRegistryKey, dr)
	return boltvm.Success(nil)
}

// Register anchors infomation for an account did.
func (dm *AccountDIDManager) Register(caller string, docAddr string, docHash []byte, sig []byte) *boltvm.Response {
	dr := dm.getAccountDIDRegistry()

	if !dr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)
	if dm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dm.Caller(), caller))
	}
	if dr.SelfID != callerDID.GetChainDID() {
		return boltvm.Error(didNotOnThisChainError(string(callerDID), string(dr.SelfID)))
	}

	docAddr, docHash, err := dr.Registry.Register(bitxid.DID(callerDID), docAddr, docHash)
	if err != nil {
		return boltvm.Error(err.Error())
	}

	dm.SetObject(AccountDIDRegistryKey, dr)
	return boltvm.Success(nil)
}

// Update updates did infomation.
func (dm *AccountDIDManager) Update(caller string, docAddr string, docHash []byte, sig []byte) *boltvm.Response {
	dr := dm.getAccountDIDRegistry()

	if !dr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)
	if dm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dm.Caller(), caller))
	}
	if dr.SelfID != callerDID.GetChainDID() {
		return boltvm.Error(didNotOnThisChainError(string(callerDID), string(dr.SelfID)))
	}

	docAddr, docHash, err := dr.Registry.Update(bitxid.DID(callerDID), docAddr, docHash)
	if err != nil {
		return boltvm.Error(err.Error())
	}

	dm.SetObject(AccountDIDRegistryKey, dr)
	return boltvm.Success(nil)
}

// Resolve gets all infomation of the did.
func (dm *AccountDIDManager) Resolve(caller string) *boltvm.Response {
	dr := dm.getAccountDIDRegistry()

	if !dr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)

	item, _, exist, err := dr.Registry.Resolve(callerDID)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	didInfo := DIDInfo{}
	if exist {
		didInfo = DIDInfo{
			DID:     string(item.ID),
			DocAddr: item.DocAddr,
			DocHash: item.DocHash,
			Status:  string(item.Status),
		}
	}
	b, err := bitxid.Marshal(didInfo)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(b)
}

// Freeze freezes the did in this registry,
// caller should be admin.
func (dm *AccountDIDManager) Freeze(caller, callerToFreeze string, sig []byte) *boltvm.Response {
	dr := dm.getAccountDIDRegistry()

	if !dr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)
	callerToFreezeDID := bitxid.DID(callerToFreeze)
	if dm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dm.Caller(), caller))
	}
	if !dr.Registry.HasAdmin(callerDID) {
		return boltvm.Error("caller has no permission")
	}

	item, _, _, err := dr.Registry.Resolve(callerToFreezeDID)
	if item.Status == bitxid.Frozen {
		return boltvm.Error(callerToFreeze + " was already frozen")
	}

	err = dr.Registry.Freeze(callerToFreezeDID)
	if err != nil {
		return boltvm.Error(err.Error())
	}

	dm.SetObject(AccountDIDRegistryKey, dr)
	return boltvm.Success(nil)
}

// UnFreeze unfreezes the did in the registry,
// caller should be admin.
func (dm *AccountDIDManager) UnFreeze(caller, callerToUnfreeze string, sig []byte) *boltvm.Response {
	dr := dm.getAccountDIDRegistry()

	if !dr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)
	callerToUnfreezeDID := bitxid.DID(callerToUnfreeze)
	if dm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dm.Caller(), caller))
	}
	if !dr.Registry.HasAdmin(callerDID) {
		return boltvm.Error("caller has no permission.")
	}

	item, _, _, err := dr.Registry.Resolve(callerToUnfreezeDID)
	if item.Status != bitxid.Frozen {
		return boltvm.Error(callerToUnfreeze + " was not frozen")
	}

	err = dr.Registry.UnFreeze(callerToUnfreezeDID)
	if err != nil {
		return boltvm.Error(err.Error())
	}

	dm.SetObject(AccountDIDRegistryKey, dr)
	return boltvm.Success(nil)
}

// Delete deletes the did,
// caller should be self, admin can not be deleted.
func (dm *AccountDIDManager) Delete(caller, callerToDelete string, sig []byte) *boltvm.Response {
	dr := dm.getAccountDIDRegistry()

	if !dr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)
	callerToDeleteDID := bitxid.DID(callerToDelete)
	if dm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dm.Caller(), caller))
	}
	if !dr.Registry.HasAdmin(callerDID) {
		return boltvm.Error("caller has no permission.")
	}
	if dr.Registry.HasAdmin(callerToDeleteDID) {
		return boltvm.Error("can not delete admin, rm admin first")
	}

	err := dr.Registry.Delete(callerToDeleteDID)
	if err != nil {
		return boltvm.Error(err.Error())
	}

	dm.SetObject(AccountDIDRegistryKey, dr)
	return boltvm.Success(nil)
}

// isSuperAdmin querys whether caller is the super admin of the registry.
func (dr *AccountDIDRegistry) isSuperAdmin(caller bitxid.DID) bool {
	admins := dr.Registry.GetAdmins()
	return admins[0] == caller
}

// HasAdmin querys whether caller is an admin of the registry.
func (dm *AccountDIDManager) HasAdmin(caller string) *boltvm.Response {
	dr := dm.getAccountDIDRegistry()

	callerDID := bitxid.DID(caller)
	if dm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dm.Caller(), caller))
	}

	res := dr.Registry.HasAdmin(callerDID)
	if res == true {
		return boltvm.Success([]byte("1"))
	}
	return boltvm.Success([]byte("0"))
}

// GetAdmins get admins of the registry.
func (dm *AccountDIDManager) GetAdmins() *boltvm.Response {
	dr := dm.getAccountDIDRegistry()

	admins := dr.Registry.GetAdmins()
	data, err := json.Marshal(admins)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success([]byte(data))
}

// AddAdmin add caller to the admin of the registry,
// caller should be admin.
func (dm *AccountDIDManager) AddAdmin(caller string, adminToAdd string) *boltvm.Response {
	dr := dm.getAccountDIDRegistry()

	callerDID := bitxid.DID(caller)
	if dm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dm.Caller(), caller))
	}
	if !dr.isSuperAdmin(callerDID) {
		return boltvm.Error("caller" + string(callerDID) + "doesn't have enough permission")
	}

	err := dr.Registry.AddAdmin(bitxid.DID(adminToAdd))
	if err != nil {
		return boltvm.Error(err.Error())
	}

	dm.SetObject(AccountDIDRegistryKey, dr)
	return boltvm.Success(nil)
}

// RemoveAdmin remove admin of the registry,
// caller should be super admin, super admin can not rm self.
func (dm *AccountDIDManager) RemoveAdmin(caller string, adminToRm string) *boltvm.Response {
	dr := dm.getAccountDIDRegistry()

	callerDID := bitxid.DID(caller)
	if dm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(dm.Caller(), caller))
	}
	if !dr.isSuperAdmin(callerDID) {
		return boltvm.Error("caller" + string(callerDID) + "doesn't have enough permission")
	}

	if dr.isSuperAdmin(bitxid.DID(adminToRm)) {
		return boltvm.Error("cannot rm super admin")
	}
	err := dr.Registry.RemoveAdmin(bitxid.DID(adminToRm))
	if err != nil {
		return boltvm.Error(err.Error())
	}

	dm.SetObject(AccountDIDRegistryKey, dr)
	return boltvm.Success(nil)
}

func docIDNotMatchDidError(c1 string, c2 string) string {
	return "doc ID(" + c1 + ") not match the did(" + c2 + ")"
}

func didNotOnThisChainError(did string, chainDID string) string {
	return "DID(" + did + ") not on the chain(" + chainDID + ")"
}
