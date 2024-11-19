// Copyright (c) 2024 SICK AG
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

package l4remoteiplist

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

type IPList struct {
	ipFile            string         // File containing all IPs to be matched, gets continously monitored
	ipAddresses       []netip.Addr   // List of currently loaded IP addresses that would matched
	ctx               *caddy.Context // Caddy context, used to detect when to shut down
	logger            *zap.Logger
	reloadNeededMutex sync.Mutex // Mutex to ensure proper concurrent handling of reloads
	reloadNeeded      bool       // Flag indicating whether a reload of the IPs is needed
}

// Creates a new IPList, creating the ipFile if it is not present
func NewIPList(ipFile string, ctx *caddy.Context, logger *zap.Logger) (*IPList, error) {
	ipList := &IPList{
		ipFile:       ipFile,
		ctx:          ctx,
		logger:       logger,
		reloadNeeded: true,
	}

	if !ipList.ipFileExists() {
		logger.Debug("could not find the file containing the IPs, trying to create it...")

		// Create a new file since it does not exist
		file, err := os.Create(ipFile)
		if err != nil {
			logger.Error("Error creating the IP list", zap.Error(err))
			return nil, fmt.Errorf("cannot create a new IP list: %v", err)
		}
		defer file.Close()
		logger.Debug("list of IP addresses successfully created")
	}

	return ipList, nil
}

// Check whether a IP address is currently contained in the IP list
func (b *IPList) IsMatched(ip netip.Addr) bool {
	// First reload the IP list if needed to ensure IPs are always up to date
	b.reloadNeededMutex.Lock()
	if b.reloadNeeded {
		err := b.loadIPAddresses()
		if err != nil {
			b.logger.Error("could not load IP addresses", zap.Error(err))
		} else {
			b.reloadNeeded = false
			b.logger.Debug("reloaded IP addresses")
		}
	}
	b.reloadNeededMutex.Unlock()

	for _, listIP := range b.ipAddresses {
		if listIP.Compare(ip) == 0 {
			return true
		}
	}
	return false
}

// Start to monitor the IP list
func (b *IPList) StartMonitoring() {
	go b.monitor()
}

func (b *IPList) ipFileExists() bool {
	// Make sure the IP list is a file
	st, err := os.Lstat(b.ipFile)
	if err != nil || st.IsDir() {
		return false
	}
	return true
}

func (b *IPList) monitor() {
	// Create a new watcher
	w, err := fsnotify.NewWatcher()
	if err != nil {
		b.logger.Error("error creating a new filesystem watcher", zap.Error(err))
		return
	}
	defer w.Close()

	if !b.ipFileExists() {
		b.logger.Error("list of IP addresses does not exist, nothing to monitor")
		return
	}

	// Monitor the directory of the file
	err = w.Add(filepath.Dir(b.ipFile))
	if err != nil {
		b.logger.Error("error watching the file", zap.Error(err))
		return
	}

	for {
		select {
		case <-b.ctx.Done():
			// Check if Caddy closed the context
			b.logger.Debug("caddy closed the context")
			return
		case err, ok := <-w.Errors:
			b.logger.Error("error from file watcher", zap.Error(err))
			if !ok {
				b.logger.Error("file watcher was closed")
				return
			}
		case e, ok := <-w.Events:
			if !ok {
				b.logger.Error("file watcher was closed")
				return
			}

			// Check if the IP list has changed
			if b.ipFile == e.Name && (e.Has(fsnotify.Create) || e.Has(fsnotify.Write)) {
				b.reloadNeededMutex.Lock()
				b.reloadNeeded = true
				b.reloadNeededMutex.Unlock()
			}
		}
	}
}

// Loads the IP addresses from the IP list
func (b *IPList) loadIPAddresses() error {
	if !b.ipFileExists() {
		b.logger.Error("list of IP addresses does not exist, could not load IP addresses")
		return fmt.Errorf("list of IP addresses %v does not exist, could not load IP addresses", b.ipFile)
	}

	file, err := os.Open(b.ipFile)
	if err != nil {
		b.logger.Error("error opening the IP list file", zap.Error(err))
		return fmt.Errorf("error opening the IP list file %v", b.ipFile)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if scanner.Err() != nil {
		b.logger.Error("error reading the IP list", zap.Error(err))
		return fmt.Errorf("error reading the IPs from %v", b.ipFile)
	}

	var ipAddresses []netip.Addr
	for _, ipStr := range lines {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			return fmt.Errorf("invalid remote IP address: %s", ipStr)
		}
		ipAddresses = append(ipAddresses, ip)
	}
	b.ipAddresses = ipAddresses
	return nil
}
