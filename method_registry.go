package contracts

import (
	"encoding/json"
	"os"

	"github.com/bitxhub/bitxid"
	"github.com/bitxhub/did-method-registry/converter"
	"github.com/meshplus/bitxhub-core/agency"
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/mitchellh/go-homedir"
)

// MethodInfo is used for return struct.
type MethodInfo struct {
	Method  string           // method name
	Owner   string           // owner of the method, is a did
	DocAddr string           // address where the doc file stored
	DocHash []byte           // hash of the doc file
	Doc     bitxid.MethodDoc // doc content
	Status  int              // status of method
}

// MethodRegistry represents all things of method registry.
type MethodRegistry struct {
	boltvm.Stub
	Registry   *bitxid.MethodRegistry
	Initalized bool
}

// NewMethodRegistry .
func NewMethodRegistry(r interface{}) agency.Contract {
	return &MethodRegistry{}
}

func init() {
	agency.RegisterContractConstructor("method registry", constant.MethodRegistryContractAddr.Address(), NewMethodRegistry)
}

// Init sets up the whole registry,
// caller should be admin.
func (mr *MethodRegistry) Init(caller string) *boltvm.Response {
	s := converter.StubToStorage(mr.Stub)
	r, err := bitxid.NewMethodRegistry(s, s, mr.Logger())
	if err != nil {
		return boltvm.Error("init failed, " + err.Error())
	}
	mr = &MethodRegistry{
		Registry:   r,
		Initalized: true,
	}
	return boltvm.Success([]byte("init success"))
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
	// verify sig of caller ...
	err := mr.Registry.Apply(callerDID, bitxid.DID(method))
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}

// AuditApply audits apply-request by others,
// caller should be admin.
func (mr *MethodRegistry) AuditApply(caller, method string, result bool, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) {
		boltvm.Error("caller has no authorization")
	}
	// verify sig of caller ...
	err := mr.Registry.AuditApply(bitxid.DID(method), result)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}

// Audit audits arbitrary status of the method,
// caller should be admin.
func (mr *MethodRegistry) Audit(caller, method string, status int, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	if !mr.Registry.HasAdmin(callerDID) {
		boltvm.Error("caller has no authorization")
	}
	err := mr.Registry.Audit(bitxid.DID(method), bitxid.StatusType(status))
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}

// Register anchors infomation for the method.
func (mr *MethodRegistry) Register(caller, method string, doc []byte, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	methodDoc := bitxid.MethodDoc{}
	methodDoc.Unmarshal(doc)
	// sig .
	docAddr, docHash, err := mr.Registry.Register(&methodDoc)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	methodInfo := MethodInfo{
		Method:  method,
		Owner:   caller,
		DocAddr: docAddr,
		DocHash: docHash,
	}
	b, err := bitxid.Struct2Bytes(methodInfo)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(b)
}

// Update updates method infomation.
func (mr *MethodRegistry) Update(caller, method string, doc *bitxid.MethodDoc, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	docAddr, docHash, err := mr.Registry.Update(doc)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	methodInfo := MethodInfo{
		Method:  method,
		Owner:   caller,
		DocAddr: docAddr,
		DocHash: docHash,
	}
	b, err := bitxid.Struct2Bytes(methodInfo)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(b)
}

// Resolve gets all infomation for the method in this registry.
func (mr *MethodRegistry) Resolve(caller, method string, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	item, doc, err := mr.Registry.Resolve(bitxid.DID(method))
	if err != nil {
		return boltvm.Error(err.Error())
	}
	methodInfo := MethodInfo{
		Method:  method,
		Owner:   caller,
		DocAddr: item.DocAddr,
		DocHash: item.DocHash,
		Doc:     *doc,
		Status:  int(item.Status),
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
	if !mr.Registry.HasAdmin(callerDID) {
		boltvm.Error("caller has no authorization.")
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
	if !mr.Registry.HasAdmin(callerDID) {
		boltvm.Error("caller has no authorization.")
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
	if !mr.Registry.HasAdmin(callerDID) {
		boltvm.Error("caller has no authorization.")
	}
	err := mr.Registry.Delete(bitxid.DID(method))
	if err != nil {
		return boltvm.Error(err.Error())
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
	if !mr.Registry.HasAdmin(callerDID) {
		boltvm.Error("caller has no authorization.")
	}

	err := mr.Registry.AddAdmin(bitxid.DID(adminToAdd))
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(nil)
}

func callerNotMatchError(c1 string, c2 string) string {
	return "tx.From(" + c1 + ") and caller:(" + c2 + ") not the same"
}

func pathRoot() (string, error) {
	dir := os.Getenv("BITXHUB_PATH")
	var err error
	if len(dir) == 0 {
		dir, err = homedir.Expand("~/.bitxhub")
	}
	return dir, err
}
