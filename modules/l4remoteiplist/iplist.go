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
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

type IPList struct {
	ipFile            string         // File containing all IPs / CIDRs to be matched, gets continuously monitored
	cidrs             []netip.Prefix // List of currently loaded CIDRs
	ctx               caddy.Context  // Caddy context, used to detect when to shut down
	logger            *zap.Logger
	reloadNeededMutex sync.Mutex  // Mutex to ensure proper concurrent handling of reloads
	reloadNeeded      bool        // Flag indicating whether a reload of the IPs is needed
	isRunning         atomic.Bool // Flag indicating whether monitoring is currently active
	stop              chan bool   // Channel to indicate that monitoring shall be stopped
}

// NewIPList creates a new IPList, creating the ipFile if it is not present
func NewIPList(ipFile string, ctx caddy.Context, logger *zap.Logger) (*IPList, error) {
	ipList := &IPList{
		ipFile:       ipFile,
		ctx:          ctx,
		logger:       logger,
		reloadNeeded: true,
		stop:         make(chan bool),
	}

	// make sure the directory containing the ipFile exists
	// otherwise, the fsnotify watcher will not work
	if !ipList.ipFileDirectoryExists() {
		return nil, fmt.Errorf("could not find the directory containing the IP file to monitor: %v", ipFile)
	}

	return ipList, nil
}

// IsMatched checks whether an IP address is currently contained in the IP list
func (b *IPList) IsMatched(ip netip.Addr) bool {
	if !b.isRunning.Load() {
		b.logger.Warn("match called but monitoring of IP file is not active")
	}

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

	for _, cidr := range b.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// StartMonitoring starts monitoring the IP list
func (b *IPList) StartMonitoring() {
	go b.monitor()
}

// StopMonitoring stops monitoring the IP list
func (b *IPList) StopMonitoring() {
	// stop goroutine
	b.stop <- true
}

func (b *IPList) ipFileDirectoryExists() bool {
	// Make sure the directory containing the IP list exists
	dirpath := filepath.Dir(b.ipFile)
	st, err := os.Lstat(dirpath)
	if err != nil || !st.IsDir() {
		return false
	}
	return true
}

func (b *IPList) ipFileExists() bool {
	// Make sure the IP list exists and is a file
	st, err := os.Lstat(b.ipFile)
	if err != nil || st.IsDir() {
		return false
	}
	return true
}

func (b *IPList) monitor() {
	// Set monitoring state to running
	b.isRunning.Store(true)

	// Create a new watcher
	w, err := fsnotify.NewWatcher()
	if err != nil {
		b.logger.Error("error creating a new filesystem watcher", zap.Error(err))
		b.isRunning.Store(false)
		return
	}
	defer func() {
		_ = w.Close()
	}()

	if !b.ipFileDirectoryExists() {
		b.logger.Error("directory containing the IP file to monitor does not exist")
		b.isRunning.Store(false)
		return
	}

	// Monitor the directory of the file
	err = w.Add(filepath.Dir(b.ipFile))
	if err != nil {
		b.logger.Error("error watching the file", zap.Error(err))
		b.isRunning.Store(false)
		return
	}

	for {
		select {
		case <-b.stop:
			// Stop method called
			b.logger.Debug("stop called")
			b.isRunning.Store(false)
			return
		case <-b.ctx.Done():
			// Caddy closed the context
			b.logger.Debug("caddy closed the context")
			b.isRunning.Store(false)
			return
		case err, ok := <-w.Errors:
			b.logger.Error("error from file watcher", zap.Error(err))
			if !ok {
				b.logger.Error("file watcher was closed")
				b.isRunning.Store(false)
				return
			}
		case e, ok := <-w.Events:
			if !ok {
				b.logger.Error("file watcher was closed")
				b.isRunning.Store(false)
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
		b.logger.Debug("ip file not found, nothing to monitor")
		b.cidrs = make([]netip.Prefix, 0)
		return nil
	}

	file, err := os.Open(b.ipFile)
	if err != nil {
		return fmt.Errorf("error opening the IP list file %v: %w", b.ipFile, err)
	}
	defer func() {
		_ = file.Close()
	}()

	var cidrs []netip.Prefix
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		cidr, err := caddyhttp.CIDRExpressionToPrefix(line)
		if err == nil {
			// only append valid IP addresses / CIDRs (ignore lines that
			// have not been parsed successfully, e.g. comments)
			cidrs = append(cidrs, cidr)
		}
	}
	err = scanner.Err()
	if err != nil {
		return fmt.Errorf("error reading the IPs from %v: %w", b.ipFile, err)
	}

	b.cidrs = cidrs
	return nil
}
