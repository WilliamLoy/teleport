/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"net"
	"strings"
)

// IsLoopback returns 'true' if a given hostname resolves *only* to the
// local host's loopback interface
func IsLoopback(host string) bool {
	if strings.Contains(host, ":") {
		var err error
		host, _, err = net.SplitHostPort(host)
		if err != nil {
			return false
		}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}

	if len(ips) == 0 {
		return false
	}

	for _, ip := range ips {
		if !ip.IsLoopback() {
			return false
		}
	}

	return true
}
