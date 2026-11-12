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
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// RegisterOrExisting registers c on reg, or returns the already-registered
// equivalent collector if an identical one is present. Several handlers of the
// same kind in one config share the same instance registry, so the second and
// subsequent Provision calls must reuse the collectors instead of panicking on
// a duplicate registration (see issue #445).
func RegisterOrExisting[C prometheus.Collector](reg *prometheus.Registry, c C) C {
	if err := reg.Register(c); err != nil {
		if are, ok := errors.AsType[prometheus.AlreadyRegisteredError](err); ok {
			if existing, ok := are.ExistingCollector.(C); ok {
				return existing
			}
		}
		// Any other registration error means the metric is unusable; fall back to
		// the unregistered collector so recording is a harmless no-op rather than
		// crashing the whole server.
	}
	return c
}
