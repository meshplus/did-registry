package contracts

import (
	"encoding/json"
	"os"

	"github.com/bitxhub/bitxid"
	"github.com/bitxhub/did-method-registry/converter"
	"github.com/meshplus/bitxhub-core/agency"
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	"github.com/mitchellh/go-homedir"
	"github.com/treasersimplifies/cstr"
)

// MethodInfo is used for return struct.
// TDDO: rm to pb.
type MethodInfo struct {
	Method  string           // method name
	Owner   string           // owner of the method, is a did
	DocAddr string           // address where the doc file stored
	DocHash []byte           // hash of the doc file
	Doc     bitxid.MethodDoc // doc content
	Status  string           // status of method
}

// MethodRegistry represents all things of method registry.
// @SelfID: self Method ID
type MethodRegistry struct {
	boltvm.Stub
	Registry    *bitxid.MethodRegistry
	Initalized  bool
	SelfID      bitxid.DID
	ParentID    bitxid.DID
	ChildIDs    []bitxid.DID
	IDConverter map[bitxid.DID]string
}

// NewMethodRegistry .
func NewMethodRegistry() agency.Contract {
	return &MethodRegistry{}
}

func init() {
	agency.RegisterContractConstructor("method registry", constant.MethodRegistryContractAddr.Address(), NewMethodRegistry)
}

// Init sets up the whole registry,
// caller will be admin of the registry.
func (mr *MethodRegistry) Init(caller string) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}

	if mr.Initalized {
		return boltvm.Error("init err, already init")
	}
	s := converter.StubToStorage(mr.Stub)
	r, err := bitxid.NewMethodRegistry(s, mr.Logger(), bitxid.WithMethodAdmin(callerDID))
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
	mr.Logger().Info(cstr.Dye("Method Registry init success with admin: "+string(callerDID), "Green"))
	return boltvm.Success(nil)
}

// SetParent sets parent for the registry
// caller should be admin.
func (mr *MethodRegistry) SetParent(caller, parentID string) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller has no authorization")
	}

	mr.ParentID = bitxid.DID(parentID)
	return boltvm.Success(nil)
}

// AddChild adds child for the registry
// caller should be admin.
func (mr *MethodRegistry) AddChild(caller, childID string) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller has no authorization")
	}

	mr.ChildIDs = append(mr.ChildIDs, bitxid.DID(childID))
	return boltvm.Success(nil)
}

// RemoveChild removes child for the registry
// caller should be admin.
func (mr *MethodRegistry) RemoveChild(caller, childID string) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller has no authorization")
	}

	for i, child := range mr.ChildIDs {
		if child == bitxid.DID(childID) {
			mr.ChildIDs = append(mr.ChildIDs[:i], mr.ChildIDs[i:]...)
		}
	}
	return boltvm.Success(nil)
}

// SetConvertMap .
// caller should be admin.
func (mr *MethodRegistry) SetConvertMap(caller, did string, appID string) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller has no authorization")
	}

	mr.IDConverter[bitxid.DID(did)] = appID
	return boltvm.Success(nil)
}

// GetConvertMap .
func (mr *MethodRegistry) GetConvertMap(caller, did string) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}

	return boltvm.Success([]byte(mr.IDConverter[bitxid.DID(did)]))
}

// Apply applys for a method name.
func (mr *MethodRegistry) Apply(caller, method string, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}

	methodDID := bitxid.DID(method)
	if !methodDID.IsValidFormat() {
		return boltvm.Error("not valid method format")
	}
	err := mr.Registry.Apply(callerDID, bitxid.DID(method)) // success
	if err != nil {
		return boltvm.Error("apply err, " + err.Error())
	}
	return boltvm.Success(nil)
}

// AuditApply audits apply-request by others,
// caller should be admin.
func (mr *MethodRegistry) AuditApply(caller, method string, result int32, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller has no authorization")
	}

	var res bool
	if result >= 1 {
		res = true
	} else {
		res = false
	}
	// TODO: verify sig
	err := mr.Registry.AuditApply(bitxid.DID(method), res)
	if err != nil {
		return boltvm.Error("audit apply err, " + err.Error())
	}
	return boltvm.Success(nil)
}

// Audit audits arbitrary status of the method,
// caller should be admin.
func (mr *MethodRegistry) Audit(caller, method string, status string, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}

	if !mr.Registry.HasAdmin(callerDID) {
		return boltvm.Error("caller has no authorization")
	}
	err := mr.Registry.Audit(bitxid.DID(method), bitxid.StatusType(status))
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}

// Register anchors infomation for the method.
func (mr *MethodRegistry) Register(caller, method string, docAddr string, docHash []byte, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}

	item, _, _, err := mr.Registry.Resolve(bitxid.DID(method))
	if item.Owner != callerDID {
		return boltvm.Error(methodNotBelongError(method, caller))
	}
	// TODO: verify sig
	_, _, err = mr.Registry.Register(bitxid.DocOption{
		ID:   bitxid.DID(method),
		Addr: docAddr,
		Hash: docHash,
	})
	if err != nil {
		return boltvm.Error("register err, " + err.Error())
	}
	return boltvm.Success(nil)
	// TODO: construct chain multi sigs
	// return mr.synchronizeOut(string(callerDID), item, [][]byte{[]byte(".")})
}

// Update updates method infomation.
func (mr *MethodRegistry) Update(caller, method string, docAddr string, docHash []byte, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}

	item, _, _, err := mr.Registry.Resolve(bitxid.DID(method))
	if item.Owner != callerDID {
		return boltvm.Error(methodNotBelongError(method, caller))
	}
	_, _, err = mr.Registry.Update(bitxid.DocOption{
		ID:   bitxid.DID(method),
		Addr: docAddr,
		Hash: docHash,
	})
	if err != nil {
		return boltvm.Error("update err, " + err.Error())
	}
	return boltvm.Success(nil)
}

// Resolve gets all infomation for the method in this registry.
func (mr *MethodRegistry) Resolve(method string) *boltvm.Response {

	item, _, exist, err := mr.Registry.Resolve(bitxid.DID(method))
	if err != nil {
		return boltvm.Error(err.Error())
	}
	if !exist {
		return boltvm.Error("Not found")
		// content := pb.Content{
		// 	SrcContractId: mr.Callee(),
		// 	DstContractId: mr.Callee(),
		// 	Func:          "Resolve",
		// 	Args:          [][]byte{[]byte(caller), []byte(method), []byte(sig)},
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
	methodInfo := MethodInfo{
		Method:  string(item.ID),
		Owner:   string(item.Owner),
		DocAddr: item.DocAddr,
		DocHash: item.DocHash,
		Status:  string(item.Status),
	}
	b, err := bitxid.Struct2Bytes(methodInfo)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(b)
}

// Freeze freezes the method in the registry,
// caller should be admin.
func (mr *MethodRegistry) Freeze(caller, method string, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller has no authorization.")
	}

	err := mr.Registry.Freeze(bitxid.DID(method))
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}

// UnFreeze unfreezes the method,
// caller should be admin.
func (mr *MethodRegistry) UnFreeze(caller, method string, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller has no authorization.")
	}

	err := mr.Registry.UnFreeze(bitxid.DID(method))
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}

// Delete deletes the method,
// caller should be admin.
func (mr *MethodRegistry) Delete(caller, method string, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller has no authorization.")
	}

	err := mr.Registry.Delete(bitxid.DID(method))
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}

// Synchronize synchronizes registry data between different registrys,
// only other registrys should call this.
// @from: sourcechain id
func (mr *MethodRegistry) Synchronize(from string, itemb []byte, sigsb []byte) *boltvm.Response {
	// callerDID := bitxid.DID(from)
	// if mr.Caller() != callerDID.GetAddress() {
	// 	return boltvm.Error(callerNotMatchError(mr.Caller(), from))
	// }
	item := &bitxid.MethodItem{}
	err := bitxid.Bytes2Struct(itemb, item)
	if err != nil {
		return boltvm.Error("synchronize err: " + err.Error())
	}
	sigs := [][]byte{}
	err = bitxid.Bytes2Struct(sigsb, &sigs)
	if err != nil {
		return boltvm.Error("synchronize err: " + err.Error())
	}
	// TODO: verify multi sigs of from chain
	err = mr.Registry.Synchronize(item)
	if err != nil {
		return boltvm.Error("synchronize err: " + err.Error())
	}
	return boltvm.Success(nil)
}

func (mr *MethodRegistry) synchronizeOut(from string, item *bitxid.MethodItem, sigs [][]byte) *boltvm.Response {
	itemBytes, err := bitxid.Struct2Bytes(item)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	sigsBytes, err := bitxid.Struct2Bytes(item)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	content := pb.Content{
		SrcContractId: mr.Callee(),
		DstContractId: mr.Callee(),
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
		res := mr.CrossInvoke(constant.InterchainContractAddr.String(), "HandleDID", pb.Bytes(data))
		if !res.Ok {
			mr.Logger().Error("synchronizeOut err, ", string(res.Result))
			return res
		}
	}
	return boltvm.Success(nil)
}

// HasAdmin querys whether caller is an admin of the registry.
func (mr *MethodRegistry) HasAdmin(caller string) *boltvm.Response {
	res := mr.Registry.HasAdmin(bitxid.DID(caller))
	if res == true {
		return boltvm.Success([]byte("1"))
	}
	return boltvm.Success([]byte("0"))
}

// GetAdmins get admin list of the registry.
func (mr *MethodRegistry) GetAdmins() *boltvm.Response {
	admins := mr.Registry.GetAdmins()
	data, err := json.Marshal(admins)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success([]byte(data))
}

// AddAdmin adds caller to the admin of the registry,
// caller should be admin.
func (mr *MethodRegistry) AddAdmin(caller string, adminToAdd string) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) { // require Admin
		return boltvm.Error("caller has no authorization.")
	}

	err := mr.Registry.AddAdmin(bitxid.DID(adminToAdd))
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}

func callerNotMatchError(c1 string, c2 string) string {
	return "tx.From(" + c1 + ") and callerDID:(" + c2 + ") not the comply"
}

func methodNotBelongError(method string, caller string) string {
	return "method (" + method + ") not belongs to caller(" + caller + ")"
}

func docIDNotMatchMethodError(c1 string, c2 string) string {
	return "doc ID(" + c1 + ") not match the method(" + c2 + ")"
}

func pathRoot() (string, error) {
	dir := os.Getenv("BITXHUB_PATH")
	var err error
	if len(dir) == 0 {
		dir, err = homedir.Expand("~/.bitxhub")
	}
	return dir, err
}
