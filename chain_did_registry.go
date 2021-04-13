package contracts

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/meshplus/bitxhub-core/agency"
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	"github.com/meshplus/bitxid"
	"github.com/meshplus/did-registry/converter"
	"github.com/mitchellh/go-homedir"
)

const (
	ChainDIDRegistryKey = "ChainDIDRegistry"
	adminMethodKey      = "admin-method"
)

// ChainDIDInfo represents information of a chain did.
// TDDO: move to pb.
type ChainDIDInfo struct {
	ChainDID string          // chainDID name
	Owner    string          // owner of the chainDID, is a did
	DocAddr  string          // address where the doc file stored
	DocHash  []byte          // hash of the doc file
	Doc      bitxid.ChainDoc // doc content
	Status   string          // status of chainDID
}

// ChainDIDManager .
type ChainDIDManager struct {
	boltvm.Stub
}

func (mm *ChainDIDManager) getChainDIDRegistry() *ChainDIDRegistry {
	mr := &ChainDIDRegistry{}
	mm.GetObject(ChainDIDRegistryKey, &mr)
	if mr.Registry != nil {
		mr.loadTable(mm.Stub)
	}
	return mr
}

// ChainDIDInterRelaychain records inter-relaychain meta data
// @OutCounter records inter-relaychian ibtp numbers of a destiny chain
type ChainDIDInterRelaychain struct {
	OutCounter map[string]uint64
	// OutMessage map[doubleKey]*pb.IBTP
}

// ChainDIDRegistry represents all things of chain did registry.
// @SelfID: self chainDID
type ChainDIDRegistry struct {
	Registry    *bitxid.ChainDIDRegistry
	Initalized  bool
	SelfID      bitxid.DID
	ParentID    bitxid.DID
	ChildIDs    []bitxid.DID
	IDConverter map[bitxid.DID]string
}

// if you need to use registry table, you have to manully load it, so do docdb
// returns err if registry is nil
func (mr *ChainDIDRegistry) loadTable(stub boltvm.Stub) error {
	if mr.Registry == nil {
		return fmt.Errorf("registry is nil")
	}
	mr.Registry.Table = &bitxid.KVTable{
		Store: converter.StubToStorage(stub),
	}
	return nil
}

// NewChainDIDManager .
func NewChainDIDManager() agency.Contract {
	return &ChainDIDManager{}
}

func init() {
	agency.RegisterContractConstructor("chain did registry", constant.MethodRegistryContractAddr.Address(), NewChainDIDManager)
}

// Init sets up the whole registry,
// caller will be admin of the registry.
func (mm *ChainDIDManager) Init(caller string) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	var admin string
	mm.GetObject(adminMethodKey, &admin)
	mm.Logger().Info("admin get: " + string(admin))

	callerDID := bitxid.DID(caller)
	if mm.Caller() != admin {
		return boltvm.Error("caller (" + mm.Caller() + ") is not admin(" + admin + ")")
	}

	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}
	if mr.Initalized {
		return boltvm.Error("init err, already init")
	}
	s := converter.StubToStorage(mm.Stub)
	r, err := bitxid.NewChainDIDRegistry(
		s,
		mm.Logger(),
		bitxid.WithAdmin(callerDID),
		bitxid.WithGenesisChainDocInfo(
			bitxid.DocInfo{ID: callerDID.GetChainDID(), Addr: ".", Hash: []byte{}},
		),
	)
	if err != nil {
		return boltvm.Error("init err, " + err.Error())
	}

	mr.Registry = r
	err = mr.Registry.SetupGenesis()
	if err != nil {
		return boltvm.Error("init genesis err, " + err.Error())
	}
	mr.SelfID = mr.Registry.GetSelfID()
	mr.ParentID = "did:bitxhub:relayroot:." // default parent
	mr.Initalized = true
	mr.IDConverter = make(map[bitxid.DID]string)
	mm.Logger().Info("Chain DID Registry init success with admin: " + string(callerDID))

	mm.SetObject(ChainDIDRegistryKey, mr)

	return boltvm.Success(nil)
}

// SetParent sets parent for the registry
// caller should be admin.
func (mm *ChainDIDManager) SetParent(caller, parentID string) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller(" + string(callerDID) + ") has no permission")
	}
	mr.ParentID = bitxid.DID(parentID)

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
}

// AddChild adds child for the registry
// caller should be admin.
func (mm *ChainDIDManager) AddChild(caller, childID string) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller(" + string(callerDID) + ") has no permission")
	}

	mr.ChildIDs = append(mr.ChildIDs, bitxid.DID(childID))

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
}

// RemoveChild removes child for the registry
// caller should be admin.
func (mm *ChainDIDManager) RemoveChild(caller, childID string) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller(" + string(callerDID) + ") has no permission")
	}

	for i, child := range mr.ChildIDs {
		if child == bitxid.DID(childID) {
			mr.ChildIDs = append(mr.ChildIDs[:i], mr.ChildIDs[i:]...)
		}
	}

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
}

func (mr *ChainDIDRegistry) setConvertMap(chainDID string, appID string) {
	mr.IDConverter[bitxid.DID(chainDID)] = appID
}

func (mr *ChainDIDRegistry) getConvertMap(chainDID string) string {
	return mr.IDConverter[bitxid.DID(chainDID)]
}

// SetConvertMap .
// caller should be admin.
func (mm *ChainDIDManager) SetConvertMap(caller, chainDID string, appID string) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller(" + string(callerDID) + ") has no permission")
	}

	mr.setConvertMap(chainDID, appID)

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
}

// GetConvertMap .
func (mm *ChainDIDManager) GetConvertMap(caller, chainDID string) *boltvm.Response {
	mr := mm.getChainDIDRegistry()
	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}
	return boltvm.Success([]byte(mr.getConvertMap(chainDID)))
}

// Apply applys for a chainDID name.
func (mm *ChainDIDManager) Apply(caller, chain string, sig []byte) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	if !mr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}

	chainDID := bitxid.DID(chain)
	if !chainDID.IsValidFormat() {
		return boltvm.Error("not valid chainDID format")
	}
	err := mr.Registry.Apply(callerDID, bitxid.DID(chainDID)) // success
	if err != nil {
		return boltvm.Error("apply err, " + err.Error())
	}

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
}

// AuditApply audits apply-request by others,
// caller should be admin.
func (mm *ChainDIDManager) AuditApply(caller, chainDID string, result int32, sig []byte) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	if !mr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller(" + string(callerDID) + ") has no permission")
	}

	var res bool
	if result >= 1 {
		res = true
	} else {
		res = false
	}
	// TODO: verify sig
	err := mr.Registry.AuditApply(bitxid.DID(chainDID), res)
	if err != nil {
		return boltvm.Error("audit apply err, " + err.Error())
	}

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
}

// Audit audits arbitrary status of the chainDID,
// caller should be admin.
func (mm *ChainDIDManager) Audit(caller, chainDID string, status string, sig []byte) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	if !mr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}

	if !mr.Registry.HasAdmin(callerDID) {
		return boltvm.Error("caller(" + string(callerDID) + ") has no permission")
	}
	err := mr.Registry.Audit(bitxid.DID(chainDID), bitxid.StatusType(status))
	if err != nil {
		return boltvm.Error(err.Error())
	}

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
}

// Register anchors infomation for the chainDID.
func (mm *ChainDIDManager) Register(caller, chainDID string, docAddr string, docHash []byte, sig []byte) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	if !mr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}

	item, _, _, err := mr.Registry.Resolve(bitxid.DID(chainDID))
	if err != nil {
		return boltvm.Error(err.Error())
	}

	if !mr.Registry.HasAdmin(callerDID) && item.Owner != callerDID {
		return boltvm.Error(notAdminOrOwnerError(chainDID, caller))
	}
	// TODO: verify sig
	_, _, err = mr.Registry.Register(bitxid.DID(chainDID), docAddr, docHash)
	if err != nil {
		return boltvm.Error("register err, " + err.Error())
	}

	item, _, _, err = mr.Registry.Resolve(bitxid.DID(chainDID))
	if err != nil {
		return boltvm.Error(err.Error())
	}

	mm.SetObject(ChainDIDRegistryKey, mr)
	data, err := bitxid.Marshal(item)

	// ibtp without index
	ibtps, err := mr.constructIBTPs(
		string(constant.MethodRegistryContractAddr),
		"Synchronize",
		string(mr.SelfID),
		func(toDIDs []bitxid.DID) []string {
			var tos []string
			for _, to := range toDIDs {
				tos = append(tos, string(to))
			}
			return tos
		}(mr.ChildIDs),
		data,
	)
	if err != nil {
		return boltvm.Error(err.Error())
	}

	ibtpsBytes, err := ibtps.Marshal()
	if err != nil {
		return boltvm.Error(err.Error())
	}

	return mm.CrossInvoke(constant.InterRelayBrokerContractAddr.String(), "RecordIBTPs", pb.Bytes(ibtpsBytes))

	// return boltvm.Success(nil)
	// TODO: construct chain multi sigs
	// return mr.synchronizeOut(string(callerDID), item, [][]byte{[]byte(".")})
}

func (mr *ChainDIDRegistry) constructIBTPs(contractID, function, fromChainDID string, toChainDIDs []string, data []byte) (*pb.IBTPs, error) {
	content := pb.Content{
		SrcContractId: contractID,
		DstContractId: contractID,
		Func:          function,
		Args:          [][]byte{[]byte(fromChainDID), []byte(data)},
		Callback:      "",
	}

	bytes, err := content.Marshal()
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(pb.Payload{
		Encrypted: false,
		Content:   bytes,
	})
	if err != nil {
		return nil, err
	}

	from := mr.getConvertMap(fromChainDID)

	var ibtps []*pb.IBTP
	for _, toChainDID := range toChainDIDs {
		to := toChainDID //
		ibtps = append(ibtps, &pb.IBTP{
			From:      from,
			To:        to,
			Type:      pb.IBTP_INTERCHAIN,
			Timestamp: time.Now().UnixNano(),
			Proof:     []byte("1"),
			Payload:   payload,
		})
	}

	return &pb.IBTPs{Ibtps: ibtps}, nil
}

// Event .
type Event struct {
	contractID   string
	function     string
	fromChainDID string
	data         []byte
	tos          []string
}

// Update updates chainDID infomation.
func (mm *ChainDIDManager) Update(caller, chainDID string, docAddr string, docHash []byte, sig []byte) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	if !mr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}

	item, _, _, err := mr.Registry.Resolve(bitxid.DID(chainDID))
	if !mr.Registry.HasAdmin(callerDID) && item.Owner != callerDID {
		return boltvm.Error(notAdminOrOwnerError(chainDID, caller))
	}
	_, _, err = mr.Registry.Update(bitxid.DID(chainDID), docAddr, docHash)
	if err != nil {
		return boltvm.Error("update err, " + err.Error())
	}

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
}

// Resolve gets all infomation for the chainDID in this registry.
func (mm *ChainDIDManager) Resolve(chainDID string) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	if !mr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	item, _, exist, err := mr.Registry.Resolve(bitxid.DID(chainDID))
	if err != nil {
		return boltvm.Error(err.Error())
	}

	chainDIDInfo := ChainDIDInfo{}
	if exist {
		chainDIDInfo = ChainDIDInfo{
			ChainDID: string(item.ID),
			Owner:    string(item.Owner),
			DocAddr:  item.DocAddr,
			DocHash:  item.DocHash,
			Status:   string(item.Status),
		}
		// Used for inter-relaychain :
		//
		// content := pb.Content{
		// 	SrcContractId: mr.Callee(),
		// 	DstContractId: mr.Callee(),
		// 	Func:          "Resolve",
		// 	Args:          [][]byte{[]byte(caller), []byte(chainDID), []byte(sig)},
		// 	Callback:      "Synchronize",
		// }
		// bytes, err := content.Marshal()
		// if err != nil {
		// 	return boltvm.Error(err.Error())
		// }
		// payload, err := json.Marshal(pb.Payload{
		// 	Encrypted: false,
		// 	Content:   bytes,
		// })
		// if err != nil {
		// 	return boltvm.Error(err.Error())
		// }
		// ibtp := pb.IBTP{
		// 	From:    mr.IDConverter[mr.SelfID],
		// 	To:      mr.IDConverter[mr.ParentID],
		// 	Payload: payload,
		// 	Proof:   []byte("."), // TODO: add proof
		// }
		// data, err := ibtp.Marshal()
		// if err != nil {
		// 	return boltvm.Error(err.Error())
		// }
		// res := mr.CrossInvoke(constant.InterchainContractAddr.String(), "HandleDID", pb.Bytes(data))
		// if !res.Ok {
		// 	return res
		// }
		// return boltvm.Success([]byte("routing..."))
	}

	b, err := bitxid.Marshal(chainDIDInfo)
	if err != nil {
		return boltvm.Error(err.Error())
	}

	return boltvm.Success(b)
}

// Freeze freezes the chainDID in the registry,
// caller should be admin.
func (mm *ChainDIDManager) Freeze(caller, chainDID string, sig []byte) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	if !mr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller(" + string(callerDID) + ") has no permission")
	}

	item, _, _, err := mr.Registry.Resolve(bitxid.DID(chainDID))
	if item.Status == bitxid.Frozen {
		return boltvm.Error(chainDID + " was already frozen")
	}

	err = mr.Registry.Freeze(bitxid.DID(chainDID))
	if err != nil {
		return boltvm.Error(err.Error())
	}

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
}

// UnFreeze unfreezes the chainDID,
// caller should be admin.
func (mm *ChainDIDManager) UnFreeze(caller, chainDID string, sig []byte) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	if !mr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller(" + string(callerDID) + ") has no permission")
	}

	item, _, _, err := mr.Registry.Resolve(bitxid.DID(chainDID))
	if item.Status != bitxid.Frozen {
		return boltvm.Error(chainDID + " was not frozen")
	}

	err = mr.Registry.UnFreeze(bitxid.DID(chainDID))
	if err != nil {
		return boltvm.Error(err.Error())
	}

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
}

// Delete deletes the chainDID,
// caller should be did who owns the chainDID.
func (mm *ChainDIDManager) Delete(caller, chainDID string, sig []byte) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	if !mr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}

	item, _, _, err := mr.Registry.Resolve(bitxid.DID(chainDID))
	if item.Owner != callerDID {
		return boltvm.Error("caller(" + string(callerDID) + ") is not the owner of " + chainDID)
	}

	err = mr.Registry.Delete(bitxid.DID(chainDID))
	if err != nil {
		return boltvm.Error(err.Error())
	}

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
}

// Synchronize synchronizes registry data between different registrys,
// use ibtp.proof to verify, it should only be called within interchain contract.
// @from: sourcechain chainDID id
func (mm *ChainDIDManager) Synchronize(from string, itemb []byte) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	if !mr.Initalized {
		return boltvm.Error("Registry not initialized")
	}

	item := &bitxid.ChainItem{}
	err := bitxid.Unmarshal(itemb, item)
	if err != nil {
		return boltvm.Error("Synchronize err: " + err.Error())
	}
	// TODO: verify multi sigs of from chain
	// sigs := [][]byte{}
	// err = bitxid.Bytes2Struct(sigsb, &sigs)
	// if err != nil {
	// 	return boltvm.Error("synchronize err: " + err.Error())
	// }

	err = mr.Registry.Synchronize(item)
	if err != nil {
		return boltvm.Error("Synchronize err: " + err.Error())
	}

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
	// TODO add receipt proof if callback enabled
}

func (mm *ChainDIDManager) synchronizeOut(from string, item *bitxid.ChainItem, sigs [][]byte) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	itemBytes, err := bitxid.Marshal(item)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	sigsBytes, err := bitxid.Marshal(item)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	content := pb.Content{
		SrcContractId: mm.Callee(),
		DstContractId: mm.Callee(),
		Func:          "Synchronize",
		Args:          [][]byte{[]byte(from), itemBytes, sigsBytes},
		Callback:      "",
	}
	bytes, err := content.Marshal()
	if err != nil {
		return boltvm.Error(err.Error())
	}
	payload, err := json.Marshal(pb.Payload{
		Encrypted: false,
		Content:   bytes,
	})
	if err != nil {
		return boltvm.Error(err.Error())
	}
	fromChainID := mr.IDConverter[mr.SelfID]
	for _, child := range mr.ChildIDs {
		toChainID := mr.IDConverter[child]
		ibtp := pb.IBTP{
			From:    fromChainID,
			To:      toChainID, // TODO
			Payload: payload,
		}
		data, err := ibtp.Marshal()
		if err != nil {
			return boltvm.Error(err.Error())
		}
		res := mm.CrossInvoke(constant.InterchainContractAddr.String(), "HandleDID", pb.Bytes(data))
		if !res.Ok {
			mm.Logger().Error("synchronizeOut err, ", string(res.Result))
			return res
		}
	}

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
}

// IsSuperAdmin querys whether caller is the super admin of the registry.
func (mr *ChainDIDRegistry) isSuperAdmin(caller bitxid.DID) bool {
	admins := mr.Registry.GetAdmins()
	return admins[0] == caller
}

// HasAdmin querys whether caller is an admin of the registry.
func (mm *ChainDIDManager) HasAdmin(caller string) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	res := mr.Registry.HasAdmin(bitxid.DID(caller))
	if res == true {
		return boltvm.Success([]byte("1"))
	}
	return boltvm.Success([]byte("0"))
}

// GetAdmins get admin list of the registry.
func (mm *ChainDIDManager) GetAdmins() *boltvm.Response {
	mr := &ChainDIDRegistry{}
	mm.GetObject(ChainDIDRegistryKey, &mr)

	admins := mr.Registry.GetAdmins()
	data, err := json.Marshal(admins)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success([]byte(data))
}

// AddAdmin adds caller to the admin of the registry,
// caller should be super admin.
func (mm *ChainDIDManager) AddAdmin(caller string, adminToAdd string) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}
	if !mr.isSuperAdmin(callerDID) { // require Admin
		return boltvm.Error("caller(" + string(callerDID) + ") doesn't have enough permission")
	}

	err := mr.Registry.AddAdmin(bitxid.DID(adminToAdd))
	if err != nil {
		return boltvm.Error(err.Error())
	}

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
}

// RemoveAdmin remove admin of the registry,
// caller should be super admin, super admin can not rm self.
func (mm *ChainDIDManager) RemoveAdmin(caller string, adminToRm string) *boltvm.Response {
	mr := mm.getChainDIDRegistry()

	callerDID := bitxid.DID(caller)
	if mm.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mm.Caller(), caller))
	}
	if !mr.isSuperAdmin(callerDID) { // require super Admin
		return boltvm.Error("caller(" + string(callerDID) + ") doesn't have enough permission")
	}
	if !mr.Registry.HasAdmin(bitxid.DID(adminToRm)) {
		return boltvm.Error("caller (" + caller + ") is not admin")
	}
	if mr.isSuperAdmin(bitxid.DID(adminToRm)) {
		return boltvm.Error("cannot rm super admin")
	}

	err := mr.Registry.RemoveAdmin(bitxid.DID(adminToRm))
	if err != nil {
		return boltvm.Error(err.Error())
	}

	mm.SetObject(ChainDIDRegistryKey, mr)
	return boltvm.Success(nil)
}

func callerNotMatchError(c1 string, c2 string) string {
	return "tx.From(" + c1 + ") and callerDID:(" + c2 + ") not the comply"
}

func notAdminOrOwnerError(chainDID string, caller string) string {
	return "caller(" +  caller + ") is not registry admin and is not owner for chainDID(" + chainDID +  ")."
}

func docIDNotMatchDIDError(c1 string, c2 string) string {
	return "doc ID(" + c1 + ") not match the chainDID(" + c2 + ")"
}

func pathRoot() (string, error) {
	dir := os.Getenv("BITXHUB_PATH")
	var err error
	if len(dir) == 0 {
		dir, err = homedir.Expand("~/.bitxhub")
	}
	return dir, err
}
