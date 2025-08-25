// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package l4proxy

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"testing"
)

func TestHostByHashing(t *testing.T) {
	upstreamCount := 254
	keyCount := 9
	matchCount := 2

	selectResults := map[string]string{}

	mockPool := func() []*Upstream {
		var result []*Upstream
		var upstreamDial []string
		for i := range upstreamCount {
			if i%3 == 0 {
				upstreamDial = []string{fmt.Sprintf("192.168.0.%d:8001,192.168.0.%d:9001", i+1, i+1)}
			} else {
				upstreamDial = []string{fmt.Sprintf("192.168.0.%d:8001", i+1)}
			}

			result = append(result, &Upstream{
				Dial: upstreamDial,
			})
		}
		return result
	}()

	mockKeys := func() []string {
		// see https://gist.github.com/porjo/f1e6b79af77893ee71e857dfba2f8e9a
		var result []string
		buf := make([]byte, 4)
		for range keyCount {
			ip := rand.Uint32()
			binary.LittleEndian.PutUint32(buf, ip)
			result = append(result, net.IP(buf).String())
		}
		return result
	}()

	for i := range matchCount {
		for _, mockKey := range mockKeys {
			selected := hostByHashing(mockPool, mockKey)
			t.Logf("[match#%d] %s -> %s", i, mockKey, selected.String())

			if selectResults[mockKey] != "" && selectResults[mockKey] != selected.String() {
				t.FailNow()
			}
			if i == 0 {
				selectResults[mockKey] = selected.String()
			}
		}
	}
}
