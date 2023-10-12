// Copyright (C) 2019-2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package merkledb

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/maybe"
)

func FuzzCodecBool(f *testing.F) {
	f.Fuzz(
		func(
			t *testing.T,
			b []byte,
		) {
			require := require.New(t)

			codec := codec.(*codecImpl)
			reader := &sliceReader{data: b}
			startLen := reader.Len()
			got, err := codec.decodeBool(reader)
			if err != nil {
				t.SkipNow()
			}
			endLen := reader.Len()
			numRead := startLen - endLen

			// Encoding [got] should be the same as [b].
			var buf bytes.Buffer
			codec.encodeBool(&buf, got)
			bufBytes := buf.Bytes()
			require.Len(bufBytes, numRead)
			require.Equal(b[:numRead], bufBytes)
		},
	)
}

func FuzzCodecInt(f *testing.F) {
	f.Fuzz(
		func(
			t *testing.T,
			b []byte,
		) {
			require := require.New(t)

			codec := codec.(*codecImpl)
			reader := &sliceReader{data: b}
			startLen := reader.Len()
			got, err := codec.decodeUint(reader)
			if err != nil {
				t.SkipNow()
			}
			endLen := reader.Len()
			numRead := startLen - endLen

			// Encoding [got] should be the same as [b].
			var buf bytes.Buffer
			codec.encodeUint(&buf, got)
			bufBytes := buf.Bytes()
			require.Len(bufBytes, numRead)
			require.Equal(b[:numRead], bufBytes)
		},
	)
}

func FuzzCodecPath(f *testing.F) {
	f.Fuzz(
		func(
			t *testing.T,
			b []byte,
		) {
			require := require.New(t)
			for _, branchFactor := range branchFactors {
				codec := codec.(*codecImpl)
				reader := &sliceReader{data: b}
				startLen := reader.Len()
				got, err := codec.decodePath(reader, branchFactor)
				if err != nil {
					t.SkipNow()
				}
				endLen := reader.Len()
				numRead := startLen - endLen

				// Encoding [got] should be the same as [b].
				var buf bytes.Buffer
				codec.encodePath(&buf, got)
				bufBytes := buf.Bytes()
				require.Len(bufBytes, numRead)
				require.Equal(b[:numRead], bufBytes)
			}
		},
	)
}

func FuzzCodecDBNodeCanonical(f *testing.F) {
	f.Fuzz(
		func(
			t *testing.T,
			b []byte,
		) {
			require := require.New(t)
			for _, branchFactor := range branchFactors {
				codec := codec.(*codecImpl)
				node := &dbNode{}
				if err := codec.decodeDBNode(b, node, branchFactor); err != nil {
					t.SkipNow()
				}

				// Encoding [node] should be the same as [b].
				buf := codec.encodeDBNode(node)
				require.Equal(b, buf)
			}
		},
	)
}

func FuzzCodecSize(f *testing.F) {
	f.Fuzz(
		func(
			t *testing.T,
			val uint64,
		) {
			require := require.New(t)
			var buf bytes.Buffer
			codec.(*codecImpl).encodeUint(&buf, val)
			require.Equal(buf.Len(), uintSize(val))
		})
}

func FuzzCodecDBNodeDeterministic(f *testing.F) {
	f.Fuzz(
		func(
			t *testing.T,
			randSeed int,
			hasValue bool,
			valueBytes []byte,
			key []byte,
		) {
			require := require.New(t)
			for _, branchFactor := range branchFactors {
				r := rand.New(rand.NewSource(int64(randSeed))) // #nosec G404

				value := maybe.Nothing[[]byte]()
				if hasValue {
					if len(valueBytes) == 0 {
						// We do this because when we encode a value of []byte{}
						// we will later decode it as nil.
						// Doing this prevents inconsistency when comparing the
						// encoded and decoded values below.
						valueBytes = nil
					}
					value = maybe.Some(valueBytes)
				}

				numChildren := r.Intn(int(branchFactor)) // #nosec G404

				children := make([]*child, branchFactor)
				for i := 0; i < numChildren; i++ {
					var childID ids.ID
					_, _ = r.Read(childID[:]) // #nosec G404

					childPathBytes := make([]byte, r.Intn(32)) // #nosec G404
					_, _ = r.Read(childPathBytes)              // #nosec G404

					children[byte(i)] = &child{
						compressedPath: NewPath(childPathBytes, branchFactor),
						id:             childID,
					}
				}
				n := dbNode{
					value:      value,
					children:   children,
					childCount: numChildren,
				}

				nodeBytes := codec.encodeDBNode(&n)

				gotNode := dbNode{}
				require.NoError(codec.decodeDBNode(nodeBytes, &gotNode, branchFactor))
				require.Equal(n, gotNode)

				nodeBytes2 := codec.encodeDBNode(&gotNode)
				require.Equal(nodeBytes, nodeBytes2)
			}
		},
	)
}

func TestCodecDecodeDBNode(t *testing.T) {
	require := require.New(t)

	var (
		parsedNode    dbNode
		tooShortBytes = make([]byte, minDBNodeLen-1)
	)
	err := codec.decodeDBNode(tooShortBytes, &parsedNode, BranchFactor16)
	require.ErrorIs(err, io.ErrUnexpectedEOF)

	proof := dbNode{
		value:    maybe.Some([]byte{1}),
		children: make([]*child, BranchFactor16),
	}

	nodeBytes := codec.encodeDBNode(&proof)
	// Remove num children (0) from end
	nodeBytes = nodeBytes[:len(nodeBytes)-minVarIntLen]
	proofBytesBuf := bytes.NewBuffer(nodeBytes)

	// Put num children > branch factor
	codec.(*codecImpl).encodeUint(proofBytesBuf, uint64(BranchFactor16+1))

	err = codec.decodeDBNode(proofBytesBuf.Bytes(), &parsedNode, BranchFactor16)
	require.ErrorIs(err, errTooManyChildren)
}

// Ensure that encodeHashValues is deterministic
func FuzzEncodeHashValues(f *testing.F) {
	codec1 := newCodec()
	codec2 := newCodec()

	f.Fuzz(
		func(
			t *testing.T,
			randSeed int,
		) {
			require := require.New(t)
			for _, branchFactor := range branchFactors { // Create a random *hashValues
				r := rand.New(rand.NewSource(int64(randSeed))) // #nosec G404

				children := make([]*child, branchFactor)
				numChildren := r.Intn(int(branchFactor)) // #nosec G404
				for i := 0; i < numChildren; i++ {
					compressedPathLen := r.Intn(32) // #nosec G404
					compressedPathBytes := make([]byte, compressedPathLen)
					_, _ = r.Read(compressedPathBytes) // #nosec G404

					children[byte(i)] = &child{
						compressedPath: NewPath(compressedPathBytes, branchFactor),
						id:             ids.GenerateTestID(),
						hasValue:       r.Intn(2) == 1, // #nosec G404
					}
				}

				hasValue := r.Intn(2) == 1 // #nosec G404
				value := maybe.Nothing[[]byte]()
				if hasValue {
					valueBytes := make([]byte, r.Intn(64)) // #nosec G404
					_, _ = r.Read(valueBytes)              // #nosec G404
					value = maybe.Some(valueBytes)
				}

				key := make([]byte, r.Intn(32)) // #nosec G404
				_, _ = r.Read(key)              // #nosec G404

				hv := &node{
					key: NewPath(key, branchFactor),
					dbNode: dbNode{
						children: children,
						value:    value,
					},
				}

				// Serialize the *hashValues with both codecs
				buf1 := bytes.NewBuffer(make([]byte, 32))
				buf2 := bytes.NewBuffer(make([]byte, 32))
				codec1.encodeHashValues(buf1, hv)
				codec2.encodeHashValues(buf2, hv)

				// Make sure they're the same
				require.Equal(buf1.Bytes(), buf2.Bytes())
			}
		},
	)
}

func TestCodecDecodePathLengthOverflowRegression(t *testing.T) {
	codec := codec.(*codecImpl)
	bytes := &sliceReader{data: binary.AppendUvarint(nil, math.MaxInt)}
	_, err := codec.decodePath(bytes, BranchFactor16)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}
