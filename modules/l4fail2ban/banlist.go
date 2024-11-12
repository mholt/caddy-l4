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

package l4fail2ban

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

type BanList struct {
	banFile           string         // File containing all currently banned IPs, gets continously monitored
	bannedIpAddresses []string       // List of currently banned IP addresses
	ctx               *caddy.Context // Caddy context, used to detect when to shut down
	logger            *zap.Logger
	reloadNeededMutex sync.Mutex // Mutex to ensure proper concurrent handling of reloads
	reloadNeeded      bool       // Flag indicating whether a reload of the banned IPs is needed
}

// Creates a new BanList, creating the banFile if it is not present
func NewBanList(banFile string, ctx *caddy.Context, logger *zap.Logger) (*BanList, error) {
	banList := &BanList{
		banFile:      banFile,
		ctx:          ctx,
		logger:       logger,
		reloadNeeded: true,
	}

	if !banList.banfileExists() {
		logger.Debug("Could not find the banfile, trying to create it...")

		// Create a new banfile since it does not exist
		_, err := os.Create(banFile)
		if err != nil {
			logger.Error("Error creating the banfile", zap.Error(err))
			return nil, fmt.Errorf("cannot create a new banfile: %v", err)
		}
		logger.Debug("Banfile successfully created")
	}

	return banList, nil
}

// Check whether an IP address is currently banned
func (b *BanList) IsBanned(remote_ip string) bool {
	// First reload the banlist if needed to ensure banned IPs are always up to date
	b.reloadNeededMutex.Lock()
	if b.reloadNeeded {
		b.loadIpAddresses()
		b.logger.Debug("Reloaded IP addresses")
		b.reloadNeeded = false
	}
	b.reloadNeededMutex.Unlock()

	for _, bannedIp := range b.bannedIpAddresses {
		if bannedIp == remote_ip {
			return true
		}
	}
	return false
}

// Start to monitor the banfile
func (b *BanList) StartMonitoring() {
	go b.monitor()
}

func (b *BanList) banfileExists() bool {
	// Make sure the banFile is a file
	st, err := os.Lstat(b.banFile)
	if err != nil || st.IsDir() {
		return false
	}
	return true
}

func (b *BanList) monitor() {
	// Create a new watcher
	w, err := fsnotify.NewWatcher()
	if err != nil {
		b.logger.Error("Error creating a new filesystem watcher", zap.Error(err))
		return
	}
	defer w.Close()

	if !b.banfileExists() {
		b.logger.Error("Banfile does not exist, nothing to monitor")
		return
	}

	// Monitor the directory of the file
	err = w.Add(filepath.Dir(b.banFile))
	if err != nil {
		b.logger.Error("Error watching the file", zap.Error(err))
		return
	}

	for {
		select {
		case <-b.ctx.Done():
			// Check if Caddy closed the context
			b.logger.Debug("Caddy closed the context")
			return
		case err, ok := <-w.Errors:
			b.logger.Error("Error from file watcher", zap.Error(err))
			if !ok {
				b.logger.Error("File watcher was closed")
				return
			}
		case e, ok := <-w.Events:
			if !ok {
				b.logger.Error("File watcher was closed")
				return
			}

			// Check if the banFile has changed
			if b.banFile == e.Name && (e.Has(fsnotify.Create) || e.Has(fsnotify.Write)) {
				b.reloadNeededMutex.Lock()
				b.reloadNeeded = true
				b.reloadNeededMutex.Unlock()
			}
		}
	}
}

// Loads the banned IP addresses from the banFile
func (b *BanList) loadIpAddresses() {
	if !b.banfileExists() {
		b.logger.Error("Banfile does not exist, could not load IP addresses")
		return
	}

	file, err := os.Open(b.banFile)
	if err != nil {
		b.logger.Error("Error opening the banned IPs file", zap.Error(err))
		return
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if scanner.Err() != nil {
		b.logger.Error("Error reading the banned IPs", zap.Error(err))
		return
	}

	b.bannedIpAddresses = lines
}
