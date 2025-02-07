// Copyright (C) 2019-2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package merkledb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/semaphore"

	"go.opentelemetry.io/otel/attribute"

	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/ava-labs/avalanchego/database"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/trace"
	"github.com/ava-labs/avalanchego/utils"
	"github.com/ava-labs/avalanchego/utils/math"
	"github.com/ava-labs/avalanchego/utils/maybe"
	"github.com/ava-labs/avalanchego/utils/set"
	"github.com/ava-labs/avalanchego/utils/units"
)

const (

	// TODO: name better
	rebuildViewSizeFractionOfCacheSize   = 50
	minRebuildViewSizePerCommit          = 1000
	rebuildIntermediateDeletionWriteSize = units.MiB
	valueNodePrefixLen                   = 1
)

var (
	rootKey []byte
	_       MerkleDB = (*merkleDB)(nil)

	codec = newCodec()

	metadataPrefix         = []byte{0}
	valueNodePrefix        = []byte{1}
	intermediateNodePrefix = []byte{2}

	cleanShutdownKey        = []byte(string(metadataPrefix) + "cleanShutdown")
	hadCleanShutdown        = []byte{1}
	didNotHaveCleanShutdown = []byte{0}

	errSameRoot  = errors.New("start and end root are the same")
	errNoNewRoot = errors.New("there was no updated root in change list")
)

type ChangeProofer interface {
	// GetChangeProof returns a proof for a subset of the key/value changes in key range
	// [start, end] that occurred between [startRootID] and [endRootID].
	// Returns at most [maxLength] key/value pairs.
	// Returns [ErrInsufficientHistory] if this node has insufficient history
	// to generate the proof.
	GetChangeProof(
		ctx context.Context,
		startRootID ids.ID,
		endRootID ids.ID,
		start maybe.Maybe[[]byte],
		end maybe.Maybe[[]byte],
		maxLength int,
	) (*ChangeProof, error)

	// Returns nil iff all of the following hold:
	//   - [start] <= [end].
	//   - [proof] is non-empty.
	//   - All keys in [proof.KeyValues] and [proof.DeletedKeys] are in [start, end].
	//     If [start] is nothing, all keys are considered > [start].
	//     If [end] is nothing, all keys are considered < [end].
	//   - [proof.KeyValues] and [proof.DeletedKeys] are sorted in order of increasing key.
	//   - [proof.StartProof] and [proof.EndProof] are well-formed.
	//   - When the changes in [proof.KeyChanes] are applied,
	//     the root ID of the database is [expectedEndRootID].
	VerifyChangeProof(
		ctx context.Context,
		proof *ChangeProof,
		start maybe.Maybe[[]byte],
		end maybe.Maybe[[]byte],
		expectedEndRootID ids.ID,
	) error

	// CommitChangeProof commits the key/value pairs within the [proof] to the db.
	CommitChangeProof(ctx context.Context, proof *ChangeProof) error
}

type RangeProofer interface {
	// GetRangeProofAtRoot returns a proof for the key/value pairs in this trie within the range
	// [start, end] when the root of the trie was [rootID].
	// If [start] is Nothing, there's no lower bound on the range.
	// If [end] is Nothing, there's no upper bound on the range.
	GetRangeProofAtRoot(
		ctx context.Context,
		rootID ids.ID,
		start maybe.Maybe[[]byte],
		end maybe.Maybe[[]byte],
		maxLength int,
	) (*RangeProof, error)

	// CommitRangeProof commits the key/value pairs within the [proof] to the db.
	// [start] is the smallest possible key in the range this [proof] covers.
	// [end] is the largest possible key in the range this [proof] covers.
	CommitRangeProof(ctx context.Context, start, end maybe.Maybe[[]byte], proof *RangeProof) error
}

type MerkleDB interface {
	database.Database
	Trie
	MerkleRootGetter
	ProofGetter
	ChangeProofer
	RangeProofer
}

type Config struct {
	// BranchFactor determines the number of children each node can have.
	BranchFactor BranchFactor

	// RootGenConcurrency is the number of goroutines to use when
	// generating a new state root.
	//
	// If 0 is specified, [runtime.NumCPU] will be used.
	RootGenConcurrency uint
	// The number of bytes to write to disk when intermediate nodes are evicted
	// from their cache and written to disk.
	EvictionBatchSize uint
	// The number of changes to the database that we store in memory in order to
	// serve change proofs.
	HistoryLength uint
	// The number of bytes to cache nodes with values.
	ValueNodeCacheSize uint
	// The number of bytes to cache nodes without values.
	IntermediateNodeCacheSize uint
	// If [Reg] is nil, metrics are collected locally but not exported through
	// Prometheus.
	// This may be useful for testing.
	Reg        prometheus.Registerer
	TraceLevel TraceLevel
	Tracer     trace.Tracer
}

// merkleDB can only be edited by committing changes from a trieView.
type merkleDB struct {
	// Must be held when reading/writing fields.
	lock sync.RWMutex

	// Must be held when preparing work to be committed to the DB.
	// Used to prevent editing of the trie without restricting read access
	// until the full set of changes is ready to be written.
	// Should be held before taking [db.lock]
	commitLock sync.RWMutex

	// Contains all of the key-value pairs stored by this database,
	// including metadata, intermediate nodes and value nodes.
	baseDB database.Database

	valueNodeDB        *valueNodeDB
	intermediateNodeDB *intermediateNodeDB

	// Stores change lists. Used to serve change proofs and construct
	// historical views of the trie.
	history *trieHistory

	// True iff the db has been closed.
	closed bool

	metrics merkleMetrics

	debugTracer trace.Tracer
	infoTracer  trace.Tracer

	// The root of this trie.
	root *node

	// Valid children of this trie.
	childViews []*trieView

	// calculateNodeIDsSema controls the number of goroutines inside
	// [calculateNodeIDsHelper] at any given time.
	calculateNodeIDsSema *semaphore.Weighted

	newPath  func(p []byte) Path
	rootPath Path
}

// New returns a new merkle database.
func New(ctx context.Context, db database.Database, config Config) (MerkleDB, error) {
	metrics, err := newMetrics("merkleDB", config.Reg)
	if err != nil {
		return nil, err
	}
	return newDatabase(ctx, db, config, metrics)
}

func newDatabase(
	ctx context.Context,
	db database.Database,
	config Config,
	metrics merkleMetrics,
) (*merkleDB, error) {
	rootGenConcurrency := uint(runtime.NumCPU())
	if config.RootGenConcurrency != 0 {
		rootGenConcurrency = config.RootGenConcurrency
	}

	if err := config.BranchFactor.Valid(); err != nil {
		return nil, err
	}

	newPath := func(b []byte) Path {
		return NewPath(b, config.BranchFactor)
	}

	// Share a sync.Pool of []byte between the intermediateNodeDB and valueNodeDB
	// to reduce memory allocations.
	bufferPool := &sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, defaultBufferLength)
		},
	}
	trieDB := &merkleDB{
		metrics:              metrics,
		baseDB:               db,
		valueNodeDB:          newValueNodeDB(db, bufferPool, metrics, int(config.ValueNodeCacheSize), config.BranchFactor),
		intermediateNodeDB:   newIntermediateNodeDB(db, bufferPool, metrics, int(config.IntermediateNodeCacheSize), int(config.EvictionBatchSize)),
		history:              newTrieHistory(int(config.HistoryLength), newPath),
		debugTracer:          getTracerIfEnabled(config.TraceLevel, DebugTrace, config.Tracer),
		infoTracer:           getTracerIfEnabled(config.TraceLevel, InfoTrace, config.Tracer),
		childViews:           make([]*trieView, 0, defaultPreallocationSize),
		calculateNodeIDsSema: semaphore.NewWeighted(int64(rootGenConcurrency)),
		newPath:              newPath,
		rootPath:             newPath(rootKey),
	}

	root, err := trieDB.initializeRootIfNeeded()
	if err != nil {
		return nil, err
	}

	// add current root to history (has no changes)
	trieDB.history.record(&changeSummary{
		rootID: root,
		values: map[Path]*change[maybe.Maybe[[]byte]]{},
		nodes:  map[Path]*change[*node]{},
	})

	shutdownType, err := trieDB.baseDB.Get(cleanShutdownKey)
	switch err {
	case nil:
		if bytes.Equal(shutdownType, didNotHaveCleanShutdown) {
			if err := trieDB.rebuild(ctx, int(config.ValueNodeCacheSize)); err != nil {
				return nil, err
			}
		}
	case database.ErrNotFound:
		// If the marker wasn't found then the DB is being created for the first
		// time and there is nothing to do.
	default:
		return nil, err
	}

	// mark that the db has not yet been cleanly closed
	err = trieDB.baseDB.Put(cleanShutdownKey, didNotHaveCleanShutdown)
	return trieDB, err
}

// Deletes every intermediate node and rebuilds them by re-adding every key/value.
// TODO: make this more efficient by only clearing out the stale portions of the trie.
func (db *merkleDB) rebuild(ctx context.Context, cacheSize int) error {
	db.root = newNode(nil, db.rootPath)

	// Delete intermediate nodes.
	if err := database.ClearPrefix(db.baseDB, intermediateNodePrefix, rebuildIntermediateDeletionWriteSize); err != nil {
		return err
	}

	// Add all key-value pairs back into the database.
	opsSizeLimit := math.Max(
		cacheSize/rebuildViewSizeFractionOfCacheSize,
		minRebuildViewSizePerCommit,
	)
	currentOps := make([]database.BatchOp, 0, opsSizeLimit)
	valueIt := db.NewIterator()
	defer valueIt.Release()
	for valueIt.Next() {
		if len(currentOps) >= opsSizeLimit {
			view, err := newTrieView(db, db, ViewChanges{BatchOps: currentOps, ConsumeBytes: true})
			if err != nil {
				return err
			}
			if err := view.commitToDB(ctx); err != nil {
				return err
			}
			currentOps = make([]database.BatchOp, 0, opsSizeLimit)
			// reset the iterator to prevent memory bloat
			nextValue := valueIt.Key()
			valueIt.Release()
			valueIt = db.NewIteratorWithStart(nextValue)
			continue
		}

		currentOps = append(currentOps, database.BatchOp{
			Key:   valueIt.Key(),
			Value: valueIt.Value(),
		})
	}
	if err := valueIt.Error(); err != nil {
		return err
	}
	view, err := newTrieView(db, db, ViewChanges{BatchOps: currentOps, ConsumeBytes: true})
	if err != nil {
		return err
	}
	if err := view.commitToDB(ctx); err != nil {
		return err
	}
	return db.Compact(nil, nil)
}

func (db *merkleDB) CommitChangeProof(ctx context.Context, proof *ChangeProof) error {
	db.commitLock.Lock()
	defer db.commitLock.Unlock()

	if db.closed {
		return database.ErrClosed
	}
	ops := make([]database.BatchOp, len(proof.KeyChanges))
	for i, kv := range proof.KeyChanges {
		ops[i] = database.BatchOp{
			Key:    kv.Key,
			Value:  kv.Value.Value(),
			Delete: kv.Value.IsNothing(),
		}
	}

	view, err := newTrieView(db, db, ViewChanges{BatchOps: ops})
	if err != nil {
		return err
	}
	return view.commitToDB(ctx)
}

func (db *merkleDB) CommitRangeProof(ctx context.Context, start, end maybe.Maybe[[]byte], proof *RangeProof) error {
	db.commitLock.Lock()
	defer db.commitLock.Unlock()

	if db.closed {
		return database.ErrClosed
	}

	ops := make([]database.BatchOp, len(proof.KeyValues))
	keys := set.NewSet[string](len(proof.KeyValues))
	for i, kv := range proof.KeyValues {
		keys.Add(string(kv.Key))
		ops[i] = database.BatchOp{
			Key:   kv.Key,
			Value: kv.Value,
		}
	}

	largestKey := end
	if len(proof.KeyValues) > 0 {
		largestKey = maybe.Some(proof.KeyValues[len(proof.KeyValues)-1].Key)
	}
	keysToDelete, err := db.getKeysNotInSet(start, largestKey, keys)
	if err != nil {
		return err
	}
	for _, keyToDelete := range keysToDelete {
		ops = append(ops, database.BatchOp{
			Key:    keyToDelete,
			Delete: true,
		})
	}

	// Don't need to lock [view] because nobody else has a reference to it.
	view, err := newTrieView(db, db, ViewChanges{BatchOps: ops})
	if err != nil {
		return err
	}

	return view.commitToDB(ctx)
}

func (db *merkleDB) Compact(start []byte, limit []byte) error {
	if db.closed {
		return database.ErrClosed
	}
	return db.baseDB.Compact(start, limit)
}

func (db *merkleDB) Close() error {
	db.commitLock.Lock()
	defer db.commitLock.Unlock()

	db.lock.Lock()
	defer db.lock.Unlock()

	if db.closed {
		return database.ErrClosed
	}

	db.closed = true
	db.valueNodeDB.Close()
	// Flush intermediary nodes to disk.
	if err := db.intermediateNodeDB.Flush(); err != nil {
		return err
	}

	// Successfully wrote intermediate nodes.
	return db.baseDB.Put(cleanShutdownKey, hadCleanShutdown)
}

func (db *merkleDB) PrefetchPaths(keys [][]byte) error {
	db.commitLock.RLock()
	defer db.commitLock.RUnlock()

	if db.closed {
		return database.ErrClosed
	}

	// reuse the view so that it can keep repeated nodes in memory
	tempView, err := newTrieView(db, db, ViewChanges{})
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := db.prefetchPath(tempView, key); err != nil {
			return err
		}
	}

	return nil
}

func (db *merkleDB) PrefetchPath(key []byte) error {
	db.commitLock.RLock()
	defer db.commitLock.RUnlock()

	if db.closed {
		return database.ErrClosed
	}
	tempView, err := newTrieView(db, db, ViewChanges{})
	if err != nil {
		return err
	}

	return db.prefetchPath(tempView, key)
}

func (db *merkleDB) prefetchPath(view *trieView, key []byte) error {
	pathToKey, err := view.getPathTo(db.newPath(key))
	if err != nil {
		return err
	}
	for _, n := range pathToKey {
		if n.hasValue() {
			db.valueNodeDB.nodeCache.Put(n.key, n)
		} else if err := db.intermediateNodeDB.nodeCache.Put(n.key, n); err != nil {
			return err
		}
	}

	return nil
}

func (db *merkleDB) Get(key []byte) ([]byte, error) {
	// this is a duplicate because the database interface doesn't support
	// contexts, which are used for tracing
	return db.GetValue(context.Background(), key)
}

func (db *merkleDB) GetValues(ctx context.Context, keys [][]byte) ([][]byte, []error) {
	_, span := db.debugTracer.Start(ctx, "MerkleDB.GetValues", oteltrace.WithAttributes(
		attribute.Int("keyCount", len(keys)),
	))
	defer span.End()

	// Lock to ensure no commit happens during the reads.
	db.lock.RLock()
	defer db.lock.RUnlock()

	values := make([][]byte, len(keys))
	errors := make([]error, len(keys))
	for i, key := range keys {
		values[i], errors[i] = db.getValueCopy(db.newPath(key))
	}
	return values, errors
}

// GetValue returns the value associated with [key].
// Returns database.ErrNotFound if it doesn't exist.
func (db *merkleDB) GetValue(ctx context.Context, key []byte) ([]byte, error) {
	_, span := db.debugTracer.Start(ctx, "MerkleDB.GetValue")
	defer span.End()

	db.lock.RLock()
	defer db.lock.RUnlock()

	return db.getValueCopy(db.newPath(key))
}

// getValueCopy returns a copy of the value for the given [key].
// Returns database.ErrNotFound if it doesn't exist.
// Assumes [db.lock] is read locked.
func (db *merkleDB) getValueCopy(key Path) ([]byte, error) {
	val, err := db.getValueWithoutLock(key)
	if err != nil {
		return nil, err
	}
	return slices.Clone(val), nil
}

// getValue returns the value for the given [key].
// Returns database.ErrNotFound if it doesn't exist.
// Assumes [db.lock] isn't held.
func (db *merkleDB) getValue(key Path) ([]byte, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	return db.getValueWithoutLock(key)
}

// getValueWithoutLock returns the value for the given [key].
// Returns database.ErrNotFound if it doesn't exist.
// Assumes [db.lock] is read locked.
func (db *merkleDB) getValueWithoutLock(key Path) ([]byte, error) {
	if db.closed {
		return nil, database.ErrClosed
	}

	n, err := db.getNode(key, true /* hasValue */)
	if err != nil {
		return nil, err
	}
	if n.value.IsNothing() {
		return nil, database.ErrNotFound
	}
	return n.value.Value(), nil
}

func (db *merkleDB) GetMerkleRoot(ctx context.Context) (ids.ID, error) {
	_, span := db.infoTracer.Start(ctx, "MerkleDB.GetMerkleRoot")
	defer span.End()

	db.lock.RLock()
	defer db.lock.RUnlock()

	if db.closed {
		return ids.Empty, database.ErrClosed
	}

	return db.getMerkleRoot(), nil
}

// Assumes [db.lock] is read locked.
func (db *merkleDB) getMerkleRoot() ids.ID {
	return db.root.id
}

func (db *merkleDB) GetProof(ctx context.Context, key []byte) (*Proof, error) {
	db.commitLock.RLock()
	defer db.commitLock.RUnlock()

	return db.getProof(ctx, key)
}

// Assumes [db.commitLock] is read locked.
// Assumes [db.lock] is not held
func (db *merkleDB) getProof(ctx context.Context, key []byte) (*Proof, error) {
	if db.closed {
		return nil, database.ErrClosed
	}

	view, err := newTrieView(db, db, ViewChanges{})
	if err != nil {
		return nil, err
	}
	// Don't need to lock [view] because nobody else has a reference to it.
	return view.getProof(ctx, key)
}

func (db *merkleDB) GetRangeProof(
	ctx context.Context,
	start maybe.Maybe[[]byte],
	end maybe.Maybe[[]byte],
	maxLength int,
) (*RangeProof, error) {
	db.commitLock.RLock()
	defer db.commitLock.RUnlock()

	return db.getRangeProofAtRoot(ctx, db.getMerkleRoot(), start, end, maxLength)
}

func (db *merkleDB) GetRangeProofAtRoot(
	ctx context.Context,
	rootID ids.ID,
	start maybe.Maybe[[]byte],
	end maybe.Maybe[[]byte],
	maxLength int,
) (*RangeProof, error) {
	db.commitLock.RLock()
	defer db.commitLock.RUnlock()

	return db.getRangeProofAtRoot(ctx, rootID, start, end, maxLength)
}

// Assumes [db.commitLock] is read locked.
// Assumes [db.lock] is not held
func (db *merkleDB) getRangeProofAtRoot(
	ctx context.Context,
	rootID ids.ID,
	start maybe.Maybe[[]byte],
	end maybe.Maybe[[]byte],
	maxLength int,
) (*RangeProof, error) {
	if db.closed {
		return nil, database.ErrClosed
	}
	if maxLength <= 0 {
		return nil, fmt.Errorf("%w but was %d", ErrInvalidMaxLength, maxLength)
	}

	historicalView, err := db.getHistoricalViewForRange(rootID, start, end)
	if err != nil {
		return nil, err
	}
	return historicalView.GetRangeProof(ctx, start, end, maxLength)
}

func (db *merkleDB) GetChangeProof(
	ctx context.Context,
	startRootID ids.ID,
	endRootID ids.ID,
	start maybe.Maybe[[]byte],
	end maybe.Maybe[[]byte],
	maxLength int,
) (*ChangeProof, error) {
	if start.HasValue() && end.HasValue() && bytes.Compare(start.Value(), end.Value()) == 1 {
		return nil, ErrStartAfterEnd
	}
	if startRootID == endRootID {
		return nil, errSameRoot
	}

	db.commitLock.RLock()
	defer db.commitLock.RUnlock()

	if db.closed {
		return nil, database.ErrClosed
	}

	changes, err := db.history.getValueChanges(startRootID, endRootID, start, end, maxLength)
	if err != nil {
		return nil, err
	}

	// [changedKeys] are a subset of the keys that were added or had their
	// values modified between [startRootID] to [endRootID] sorted in increasing
	// order.
	changedKeys := maps.Keys(changes.values)
	utils.Sort(changedKeys)

	result := &ChangeProof{
		KeyChanges: make([]KeyChange, 0, len(changedKeys)),
	}

	for _, key := range changedKeys {
		change := changes.values[key]

		result.KeyChanges = append(result.KeyChanges, KeyChange{
			Key: key.Bytes(),
			// create a copy so edits of the []byte don't affect the db
			Value: maybe.Bind(change.after, slices.Clone[[]byte]),
		})
	}

	largestKey := end
	if len(result.KeyChanges) > 0 {
		largestKey = maybe.Some(result.KeyChanges[len(result.KeyChanges)-1].Key)
	}

	// Since we hold [db.commitlock] we must still have sufficient
	// history to recreate the trie at [endRootID].
	historicalView, err := db.getHistoricalViewForRange(endRootID, start, largestKey)
	if err != nil {
		return nil, err
	}

	if largestKey.HasValue() {
		endProof, err := historicalView.getProof(ctx, largestKey.Value())
		if err != nil {
			return nil, err
		}
		result.EndProof = endProof.Path
	}

	if start.HasValue() {
		startProof, err := historicalView.getProof(ctx, start.Value())
		if err != nil {
			return nil, err
		}
		result.StartProof = startProof.Path

		// strip out any common nodes to reduce proof size
		commonNodeIndex := 0
		for ; commonNodeIndex < len(result.StartProof) &&
			commonNodeIndex < len(result.EndProof) &&
			result.StartProof[commonNodeIndex].KeyPath == result.EndProof[commonNodeIndex].KeyPath; commonNodeIndex++ {
		}
		result.StartProof = result.StartProof[commonNodeIndex:]
	}

	// Note that one of the following must be true:
	//  - [result.StartProof] is non-empty.
	//  - [result.EndProof] is non-empty.
	//  - [result.KeyValues] is non-empty.
	//  - [result.DeletedKeys] is non-empty.
	// If all of these were false, it would mean that no
	// [start] and [end] were given, and no diff between
	// the trie at [startRootID] and [endRootID] was found.
	// Since [startRootID] != [endRootID], this is impossible.
	return result, nil
}

// NewView returns a new view on top of this Trie where the passed changes
// have been applied.
//
// Changes made to the view will only be reflected in the original trie if
// Commit is called.
//
// Assumes [db.commitLock] and [db.lock] aren't held.
func (db *merkleDB) NewView(
	_ context.Context,
	changes ViewChanges,
) (TrieView, error) {
	// ensure the db doesn't change while creating the new view
	db.commitLock.RLock()
	defer db.commitLock.RUnlock()

	if db.closed {
		return nil, database.ErrClosed
	}

	newView, err := newTrieView(db, db, changes)
	if err != nil {
		return nil, err
	}

	// ensure access to childViews is protected
	db.lock.Lock()
	defer db.lock.Unlock()

	db.childViews = append(db.childViews, newView)
	return newView, nil
}

func (db *merkleDB) Has(k []byte) (bool, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	if db.closed {
		return false, database.ErrClosed
	}

	_, err := db.getValueWithoutLock(db.newPath(k))
	if err == database.ErrNotFound {
		return false, nil
	}
	return err == nil, err
}

func (db *merkleDB) HealthCheck(ctx context.Context) (interface{}, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	if db.closed {
		return nil, database.ErrClosed
	}
	return db.baseDB.HealthCheck(ctx)
}

func (db *merkleDB) NewBatch() database.Batch {
	return &batch{
		db: db,
	}
}

func (db *merkleDB) NewIterator() database.Iterator {
	return db.NewIteratorWithStartAndPrefix(nil, nil)
}

func (db *merkleDB) NewIteratorWithStart(start []byte) database.Iterator {
	return db.NewIteratorWithStartAndPrefix(start, nil)
}

func (db *merkleDB) NewIteratorWithPrefix(prefix []byte) database.Iterator {
	return db.NewIteratorWithStartAndPrefix(nil, prefix)
}

func (db *merkleDB) NewIteratorWithStartAndPrefix(start, prefix []byte) database.Iterator {
	return db.valueNodeDB.newIteratorWithStartAndPrefix(start, prefix)
}

func (db *merkleDB) Put(k, v []byte) error {
	return db.PutContext(context.Background(), k, v)
}

// Same as [Put] but takes in a context used for tracing.
func (db *merkleDB) PutContext(ctx context.Context, k, v []byte) error {
	db.commitLock.Lock()
	defer db.commitLock.Unlock()

	if db.closed {
		return database.ErrClosed
	}

	view, err := newTrieView(db, db, ViewChanges{BatchOps: []database.BatchOp{{Key: k, Value: v}}})
	if err != nil {
		return err
	}
	return view.commitToDB(ctx)
}

func (db *merkleDB) Delete(key []byte) error {
	return db.DeleteContext(context.Background(), key)
}

func (db *merkleDB) DeleteContext(ctx context.Context, key []byte) error {
	db.commitLock.Lock()
	defer db.commitLock.Unlock()

	if db.closed {
		return database.ErrClosed
	}

	view, err := newTrieView(db, db,
		ViewChanges{
			BatchOps: []database.BatchOp{{
				Key:    key,
				Delete: true,
			}},
			ConsumeBytes: true,
		})
	if err != nil {
		return err
	}
	return view.commitToDB(ctx)
}

// Assumes values inside of [ops] are safe to reference after the function
// returns. Assumes [db.lock] isn't held.
func (db *merkleDB) commitBatch(ops []database.BatchOp) error {
	db.commitLock.Lock()
	defer db.commitLock.Unlock()

	if db.closed {
		return database.ErrClosed
	}

	view, err := newTrieView(db, db, ViewChanges{BatchOps: ops, ConsumeBytes: true})
	if err != nil {
		return err
	}
	return view.commitToDB(context.Background())
}

// commitChanges commits the changes in [trieToCommit] to [db].
// Assumes [trieToCommit]'s node IDs have been calculated.
func (db *merkleDB) commitChanges(ctx context.Context, trieToCommit *trieView) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	switch {
	case db.closed:
		return database.ErrClosed
	case trieToCommit == nil:
		return nil
	case trieToCommit.isInvalid():
		return ErrInvalid
	case trieToCommit.committed:
		return ErrCommitted
	case trieToCommit.db != trieToCommit.getParentTrie():
		return ErrParentNotDatabase
	}

	changes := trieToCommit.changes
	_, span := db.infoTracer.Start(ctx, "MerkleDB.commitChanges", oteltrace.WithAttributes(
		attribute.Int("nodesChanged", len(changes.nodes)),
		attribute.Int("valuesChanged", len(changes.values)),
	))
	defer span.End()

	// invalidate all child views except for the view being committed
	db.invalidateChildrenExcept(trieToCommit)

	// move any child views of the committed trie onto the db
	db.moveChildViewsToDB(trieToCommit)

	if len(changes.nodes) == 0 {
		return nil
	}

	rootChange, ok := changes.nodes[db.rootPath]
	if !ok {
		return errNoNewRoot
	}

	currentValueNodeBatch := db.valueNodeDB.NewBatch()

	_, nodesSpan := db.infoTracer.Start(ctx, "MerkleDB.commitChanges.writeNodes")
	for key, nodeChange := range changes.nodes {
		shouldAddIntermediate := nodeChange.after != nil && !nodeChange.after.hasValue()
		shouldDeleteIntermediate := !shouldAddIntermediate && nodeChange.before != nil && !nodeChange.before.hasValue()

		shouldAddValue := nodeChange.after != nil && nodeChange.after.hasValue()
		shouldDeleteValue := !shouldAddValue && nodeChange.before != nil && nodeChange.before.hasValue()

		if shouldAddIntermediate {
			if err := db.intermediateNodeDB.Put(key, nodeChange.after); err != nil {
				nodesSpan.End()
				return err
			}
		} else if shouldDeleteIntermediate {
			if err := db.intermediateNodeDB.Delete(key); err != nil {
				nodesSpan.End()
				return err
			}
		}

		if shouldAddValue {
			currentValueNodeBatch.Put(key, nodeChange.after)
		} else if shouldDeleteValue {
			currentValueNodeBatch.Delete(key)
		}
	}
	nodesSpan.End()

	_, commitSpan := db.infoTracer.Start(ctx, "MerkleDB.commitChanges.valueNodeDBCommit")
	err := currentValueNodeBatch.Write()
	commitSpan.End()
	if err != nil {
		return err
	}

	// Only modify in-memory state after the commit succeeds
	// so that we don't need to clean up on error.
	db.root = rootChange.after
	db.history.record(changes)
	return nil
}

// moveChildViewsToDB removes any child views from the trieToCommit and moves them to the db
// assumes [db.lock] is held
func (db *merkleDB) moveChildViewsToDB(trieToCommit *trieView) {
	trieToCommit.validityTrackingLock.Lock()
	defer trieToCommit.validityTrackingLock.Unlock()

	for _, childView := range trieToCommit.childViews {
		childView.updateParent(db)
		db.childViews = append(db.childViews, childView)
	}
	trieToCommit.childViews = make([]*trieView, 0, defaultPreallocationSize)
}

// CommitToDB is a no-op for db since it is already in sync with itself.
// This exists to satisfy the TrieView interface.
func (*merkleDB) CommitToDB(context.Context) error {
	return nil
}

// This is defined on merkleDB instead of ChangeProof
// because it accesses database internals.
// Assumes [db.lock] isn't held.
func (db *merkleDB) VerifyChangeProof(
	ctx context.Context,
	proof *ChangeProof,
	start maybe.Maybe[[]byte],
	end maybe.Maybe[[]byte],
	expectedEndRootID ids.ID,
) error {
	switch {
	case start.HasValue() && end.HasValue() && bytes.Compare(start.Value(), end.Value()) > 0:
		return ErrStartAfterEnd
	case proof.Empty():
		return ErrNoMerkleProof
	case end.HasValue() && len(proof.KeyChanges) == 0 && len(proof.EndProof) == 0:
		// We requested an end proof but didn't get one.
		return ErrNoEndProof
	case start.HasValue() && len(proof.StartProof) == 0 && len(proof.EndProof) == 0:
		// We requested a start proof but didn't get one.
		// Note that we also have to check that [proof.EndProof] is empty
		// to handle the case that the start proof is empty because all
		// its nodes are also in the end proof, and those nodes are omitted.
		return ErrNoStartProof
	}

	// Make sure the key-value pairs are sorted and in [start, end].
	if err := verifyKeyChanges(proof.KeyChanges, start, end); err != nil {
		return err
	}

	smallestPath := maybe.Bind(start, db.newPath)

	// Make sure the start proof, if given, is well-formed.
	if err := verifyProofPath(proof.StartProof, smallestPath); err != nil {
		return err
	}

	// Find the greatest key in [proof.KeyChanges]
	// Note that [proof.EndProof] is a proof for this key.
	// [largestPath] is also used when we add children of proof nodes to [trie] below.
	largestPath := maybe.Bind(end, db.newPath)
	if len(proof.KeyChanges) > 0 {
		// If [proof] has key-value pairs, we should insert children
		// greater than [end] to ancestors of the node containing [end]
		// so that we get the expected root ID.
		largestPath = maybe.Some(db.newPath(proof.KeyChanges[len(proof.KeyChanges)-1].Key))
	}

	// Make sure the end proof, if given, is well-formed.
	if err := verifyProofPath(proof.EndProof, largestPath); err != nil {
		return err
	}

	keyValues := make(map[Path]maybe.Maybe[[]byte], len(proof.KeyChanges))
	for _, keyValue := range proof.KeyChanges {
		keyValues[db.newPath(keyValue.Key)] = keyValue.Value
	}

	// want to prevent commit writes to DB, but not prevent DB reads
	db.commitLock.RLock()
	defer db.commitLock.RUnlock()

	if db.closed {
		return database.ErrClosed
	}

	if err := verifyAllChangeProofKeyValuesPresent(
		ctx,
		db,
		proof.StartProof,
		smallestPath,
		largestPath,
		keyValues,
	); err != nil {
		return err
	}

	if err := verifyAllChangeProofKeyValuesPresent(
		ctx,
		db,
		proof.EndProof,
		smallestPath,
		largestPath,
		keyValues,
	); err != nil {
		return err
	}

	// Insert the key-value pairs into the trie.
	ops := make([]database.BatchOp, len(proof.KeyChanges))
	for i, kv := range proof.KeyChanges {
		ops[i] = database.BatchOp{
			Key:    kv.Key,
			Value:  kv.Value.Value(),
			Delete: kv.Value.IsNothing(),
		}
	}

	// Don't need to lock [view] because nobody else has a reference to it.
	view, err := newTrieView(db, db, ViewChanges{BatchOps: ops, ConsumeBytes: true})
	if err != nil {
		return err
	}

	// For all the nodes along the edges of the proof, insert the children whose
	// keys are less than [insertChildrenLessThan] or whose keys are greater
	// than [insertChildrenGreaterThan] into the trie so that we get the
	// expected root ID (if this proof is valid).
	if err := addPathInfo(
		view,
		proof.StartProof,
		smallestPath,
		largestPath,
	); err != nil {
		return err
	}
	if err := addPathInfo(
		view,
		proof.EndProof,
		smallestPath,
		largestPath,
	); err != nil {
		return err
	}

	// Make sure we get the expected root.
	calculatedRoot, err := view.GetMerkleRoot(ctx)
	if err != nil {
		return err
	}
	if expectedEndRootID != calculatedRoot {
		return fmt.Errorf("%w:[%s], expected:[%s]", ErrInvalidProof, calculatedRoot, expectedEndRootID)
	}

	return nil
}

// Invalidates and removes any child views that aren't [exception].
// Assumes [db.lock] is held.
func (db *merkleDB) invalidateChildrenExcept(exception *trieView) {
	isTrackedView := false

	for _, childView := range db.childViews {
		if childView != exception {
			childView.invalidate()
		} else {
			isTrackedView = true
		}
	}
	db.childViews = make([]*trieView, 0, defaultPreallocationSize)
	if isTrackedView {
		db.childViews = append(db.childViews, exception)
	}
}

func (db *merkleDB) initializeRootIfNeeded() (ids.ID, error) {
	// not sure if the root exists or had a value or not
	// check under both prefixes
	var err error
	db.root, err = db.intermediateNodeDB.Get(db.rootPath)
	if err == database.ErrNotFound {
		db.root, err = db.valueNodeDB.Get(db.rootPath)
	}
	if err == nil {
		// Root already exists, so calculate its id
		db.root.calculateID(db.metrics)
		return db.root.id, nil
	}
	if err != database.ErrNotFound {
		return ids.Empty, err
	}

	// Root doesn't exist; make a new one.
	db.root = newNode(nil, db.rootPath)

	// update its ID
	db.root.calculateID(db.metrics)

	if err := db.intermediateNodeDB.Put(db.rootPath, db.root); err != nil {
		return ids.Empty, err
	}

	return db.root.id, nil
}

// Returns a view of the trie as it was when it had root [rootID] for keys within range [start, end].
// If [start] is Nothing, there's no lower bound on the range.
// If [end] is Nothing, there's no upper bound on the range.
// Assumes [db.commitLock] is read locked.
// Assumes [db.lock] isn't held.
func (db *merkleDB) getHistoricalViewForRange(
	rootID ids.ID,
	start maybe.Maybe[[]byte],
	end maybe.Maybe[[]byte],
) (*trieView, error) {
	currentRootID := db.getMerkleRoot()

	// looking for the trie's current root id, so return the trie unmodified
	if currentRootID == rootID {
		// create an empty trie
		return newTrieView(db, db, ViewChanges{})
	}

	changeHistory, err := db.history.getChangesToGetToRoot(rootID, start, end)
	if err != nil {
		return nil, err
	}
	return newHistoricalTrieView(db, changeHistory)
}

// Returns all keys in range [start, end] that aren't in [keySet].
// If [start] is Nothing, then the range has no lower bound.
// If [end] is Nothing, then the range has no upper bound.
func (db *merkleDB) getKeysNotInSet(start, end maybe.Maybe[[]byte], keySet set.Set[string]) ([][]byte, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	it := db.NewIteratorWithStart(start.Value())
	defer it.Release()

	keysNotInSet := make([][]byte, 0, keySet.Len())
	for it.Next() {
		key := it.Key()
		if end.HasValue() && bytes.Compare(key, end.Value()) > 0 {
			break
		}
		if !keySet.Contains(string(key)) {
			keysNotInSet = append(keysNotInSet, key)
		}
	}
	return keysNotInSet, it.Error()
}

// Returns a copy of the node with the given [key].
// hasValue determines which db the key is looked up in (intermediateNodeDB or valueNodeDB)
// This copy may be edited by the caller without affecting the database state.
// Returns database.ErrNotFound if the node doesn't exist.
// Assumes [db.lock] isn't held.
func (db *merkleDB) getEditableNode(key Path, hasValue bool) (*node, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	n, err := db.getNode(key, hasValue)
	if err != nil {
		return nil, err
	}
	return n.clone(), nil
}

// Returns the node with the given [key].
// hasValue determines which db the key is looked up in (intermediateNodeDB or valueNodeDB)
// Editing the returned node affects the database state.
// Returns database.ErrNotFound if the node doesn't exist.
// Assumes [db.lock] is read locked.
func (db *merkleDB) getNode(key Path, hasValue bool) (*node, error) {
	switch {
	case db.closed:
		return nil, database.ErrClosed
	case key == db.rootPath:
		return db.root, nil
	case hasValue:
		return db.valueNodeDB.Get(key)
	}
	return db.intermediateNodeDB.Get(key)
}

// Returns [key] prefixed by [prefix].
// The returned []byte is taken from [bufferPool] and
// should be returned to it when the caller is done with it.
func addPrefixToKey(bufferPool *sync.Pool, prefix []byte, key []byte) []byte {
	prefixLen := len(prefix)
	keyLen := prefixLen + len(key)
	prefixedKey := getBufferFromPool(bufferPool, keyLen)
	copy(prefixedKey, prefix)
	copy(prefixedKey[prefixLen:], key)
	return prefixedKey
}

// Returns a []byte from [bufferPool] with length exactly [size].
// The []byte is not guaranteed to be zeroed.
func getBufferFromPool(bufferPool *sync.Pool, size int) []byte {
	buffer := bufferPool.Get().([]byte)
	if cap(buffer) >= size {
		// The [] byte we got from the pool is big enough to hold the prefixed key
		buffer = buffer[:size]
	} else {
		// The []byte from the pool wasn't big enough.
		// Put it back and allocate a new, bigger one
		bufferPool.Put(buffer)
		buffer = make([]byte, size)
	}
	return buffer
}

// cacheEntrySize returns a rough approximation of the memory consumed by storing the path and node
func cacheEntrySize(p Path, n *node) int {
	if n == nil {
		return len(p.Bytes())
	}
	// nodes cache their bytes representation so the total memory consumed is roughly twice that
	return len(p.Bytes()) + 2*len(n.bytes())
}
