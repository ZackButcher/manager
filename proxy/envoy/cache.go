// Copyright 2017 Istio Authors.
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

package envoy

import (
	"sync"
	"sync/atomic"

	"github.com/golang/glog"

	proxyconfig "istio.io/api/proxy/v1/config"
	"istio.io/pilot/model"
	"istio.io/pilot/proxy"
)

// trackingConfigStore is an IstioConfigStore that tracks they keys of the Istio config retrieved from it. The intent is
// that this can wrap the real IstioConfigStore implementation every time we compute a config for Envoy. This tracks the
// keys of the Istio configuration used to compute a specific Envoy config, and allows us to do perform fine-grain cache
// evictions as Istio config changes.
//
// Given the intended use case, the current implementation is not safe for concurrent use.
type trackingConfigStore struct {
	model.IstioConfigStore
	referencedKeys map[string]struct{}
}

func trackStore(store model.IstioConfigStore) (model.IstioConfigStore, map[string]struct{}) {
	refs := make(map[string]struct{})
	return &trackingConfigStore{store, refs}, refs
}

func trackEnvironment(env proxy.Environment) (proxy.Environment, map[string]struct{}) {
	store, refs := trackStore(env.IstioConfigStore)
	return proxy.Environment{
		ServiceDiscovery: env.ServiceDiscovery,
		ServiceAccounts: env.ServiceAccounts,
		IstioConfigStore: store,
		Mesh: env.Mesh,
		MixerSAN: env.MixerSAN,
	}, refs
}

// EgressRules lists all egress rules
func (w *trackingConfigStore) EgressRules() map[string]*proxyconfig.EgressRule {
	rules := w.IstioConfigStore.EgressRules()
	for key := range rules {
		w.referencedKeys[key] = struct{}{}
	}
	return rules
}

// RouteRules selects routing rules by source service instances and
// destination service.  A rule must match at least one of the input service
// instances since the proxy does not distinguish between source instances in
// the request.
func (w *trackingConfigStore) RouteRules(source []*model.ServiceInstance, destination string) []model.Config {
	rules := w.IstioConfigStore.RouteRules(source, destination)
	for _, rule := range rules {
		w.referencedKeys[rule.Key()] = struct{}{}
	}
	return rules
}

// RouteRulesByDestination selects routing rules associated with destination
// service instances.  A rule must match at least one of the input
// destination instances.
func (w *trackingConfigStore) RouteRulesByDestination(destination []*model.ServiceInstance) []model.Config {
	rules := w.IstioConfigStore.RouteRulesByDestination(destination)
	for _, rule := range rules {
		w.referencedKeys[rule.Key()] = struct{}{}
	}
	return rules
}

// Policy returns a policy for a service version that match at least one of
// the source instances.  The labels must match precisely in the policy.
func (w *trackingConfigStore) Policy(source []*model.ServiceInstance, destination string, labels model.Labels) *model.Config {
	policy := w.IstioConfigStore.Policy(source, destination, labels)
	w.referencedKeys[policy.Key()] = struct{}{}
	return policy
}

type discoveryCacheStatEntry struct {
	Hit  uint64 `json:"hit"`
	Miss uint64 `json:"miss"`
}

type discoveryCacheStats struct {
	Stats map[string]*discoveryCacheStatEntry `json:"cache_stats"`
}

type discoveryCacheEntry struct {
	data []byte
	keys map[string]struct{} // Istio config keys used to compute this cache entry
	hit  uint64 // atomic
	miss uint64 // atomic
}

type discoveryCache struct {
	disabled bool
	mu       sync.RWMutex
	cache    map[string]*discoveryCacheEntry
	// maps from Istio key to the set of primary cache keys that used the Istio config object to construct their entry
	byIstioKey     map[string]map[string]struct{}
}

func newDiscoveryCache(enabled bool) *discoveryCache {
	return &discoveryCache{
		disabled: !enabled,
		cache:    make(map[string]*discoveryCacheEntry),
		byIstioKey: make(map[string]map[string]struct{}),
	}
}
func (c *discoveryCache) cachedDiscoveryResponse(key string) ([]byte, bool) {
	if c.disabled {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Miss - entry.miss is updated in updateCachedDiscoveryResponse
	entry, ok := c.cache[key]
	if !ok || entry.data == nil {
		return nil, false
	}

	// Hit
	atomic.AddUint64(&entry.hit, 1)
	return entry.data, true
}

func (c *discoveryCache) updateCachedDiscoveryResponse(key string, istioKeys map[string]struct{}, data []byte) {
	if c.disabled {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.cache[key]
	if !ok {
		entry = &discoveryCacheEntry{}
		c.cache[key] = entry
	} else if entry.data != nil {
		glog.Warningf("Overriding cached data for entry %v", key)
	}

	for k := range istioKeys {
		entries, present := c.byIstioKey[k]
		if !present {
			entries = make(map[string]struct{})
			c.byIstioKey[k] = entries
		}
		entries[key] = struct{}{}
	}

	entry.data = data
	atomic.AddUint64(&entry.miss, 1)
}

// Clears the entire cache.
func (c *discoveryCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, v := range c.cache {
		v.data = nil
	}
	for k := range c.byIstioKey {
		c.byIstioKey[k] = make(map[string]struct{})
	}
}

// Clears all cache entries that depended on the provided Istio config key.
func (c *discoveryCache) clearByKey(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries, present := c.byIstioKey[key]
	if !present {
		return // we didn't have any cache entries that depended on this key
	}

	for entry := range entries {
		c.cache[entry].data = nil
	}
	c.byIstioKey[key] = make(map[string]struct{})
}

func (c *discoveryCache) resetStats() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, v := range c.cache {
		atomic.StoreUint64(&v.hit, 0)
		atomic.StoreUint64(&v.miss, 0)
	}
}

func (c *discoveryCache) stats() map[string]*discoveryCacheStatEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := make(map[string]*discoveryCacheStatEntry, len(c.cache))
	for k, v := range c.cache {
		stats[k] = &discoveryCacheStatEntry{
			Hit:  atomic.LoadUint64(&v.hit),
			Miss: atomic.LoadUint64(&v.miss),
		}
	}
	return stats
}
