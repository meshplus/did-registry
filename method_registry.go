package contracts

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/bitxhub/bitxid"
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub-kit/storage/leveldb"
)

const (
	repoRoot string = "./"
)

// MethodInfo .
type MethodInfo struct {
	Method  string           // method name
	Owner   string           // owner of the method, is a did
	DocAddr string           // address where the doc file stored
	DocHash []byte           // hash of the doc file
	Doc     bitxid.MethodDoc // doc content
	Status  int              // status of method
}

// MethodRegistry .
type MethodRegistry struct {
	boltvm.Stub
	Registry   *bitxid.MethodRegistry
	Initalized bool
}

// Test .
func (mr *MethodRegistry) Test(key string, value string) *boltvm.Response {
	fmt.Println("key:", key, ", value:", value)
	return boltvm.Success([]byte(key + value))
}

// Init sets up the whole registry
func (mr *MethodRegistry) Init(caller string) *boltvm.Response {

	if mr.Initalized {
		boltvm.Error("method registry already initalized")
	}

	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}

	if !mr.Registry.HasAdmin(callerDID) {
		boltvm.Error("caller has no authorization")
	}

	ts, err := leveldb.New(filepath.Join(repoRoot, "storage", "MethodRegistry"))
	if err != nil {
		return boltvm.Error(err.Error())
	}
	l := mr.Logger()                          // to be removed
	conf, err := bitxid.DefaultBitXIDConfig() // to be changed
	if err != nil {
		return boltvm.Error(err.Error())
	}

	r, err := bitxid.NewMethodRegistry(ts, ts, l, &conf.MethodConfig)
	if err != nil {
		return boltvm.Error(err.Error())
	}

	err = r.SetupGenesis()
	if err != nil {
		return boltvm.Error(err.Error())
	}

	mr.Registry = r
	mr.Initalized = true
	return boltvm.Success(nil)
}

// Apply caller applys for method name
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

// AuditApply admin caller audit apply-request by others
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

// Audit audit infomation for a method in registry
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

// Register infomation for a method in registry
func (mr *MethodRegistry) Register(caller, method string, doc []byte, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	methodDoc := bitxid.MethodDoc{}
	methodDoc.Unmarshal(doc)
	// sig .
	docAddr, docHash, err := mr.Registry.Register(methodDoc)
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

// Update updates method infomation in registry
func (mr *MethodRegistry) Update(caller, method string, doc []byte, sig []byte) *boltvm.Response {
	callerDID := bitxid.DID(caller)
	if mr.Caller() != callerDID.GetAddress() {
		return boltvm.Error(callerNotMatchError(mr.Caller(), caller))
	}
	methodDoc := bitxid.MethodDoc{}
	methodDoc.Unmarshal(doc)
	docAddr, docHash, err := mr.Registry.Update(methodDoc)
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

// Resolve gets all infomation of the method from registry
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
		Doc:     doc,
		Status:  int(item.Status),
	}
	b, err := bitxid.Struct2Bytes(methodInfo)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(b)
}

// Freeze admin caller freezes the method in registry
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

// UnFreeze admin caller unfreezes the method in registry
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

// Delete deletes the method in registry
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

// HasAdmin .
func (mr *MethodRegistry) HasAdmin(caller string) *boltvm.Response {
	res := mr.Registry.HasAdmin(bitxid.DID(caller))
	if res == true {
		return boltvm.Success([]byte("1"))
	}
	return boltvm.Success([]byte("0"))
}

// GetAdmins get admins of the registry
func (mr *MethodRegistry) GetAdmins() *boltvm.Response {
	admins := mr.Registry.GetAdmins()
	data, err := json.Marshal(admins)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success([]byte(data))
}

// AddAdmin add an admin of the registry
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
