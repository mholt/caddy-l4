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

package layer4

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestRegisterOrExisting(t *testing.T) {
	reg := prometheus.NewRegistry()
	mk := func() *prometheus.CounterVec {
		return prometheus.NewCounterVec(prometheus.CounterOpts{Name: "x_total", Help: "x"}, []string{"l"})
	}

	first := RegisterOrExisting(reg, mk())
	second := RegisterOrExisting(reg, mk()) // must not panic
	if first != second {
		t.Error("expected the second registration to return the existing collector")
	}
}
