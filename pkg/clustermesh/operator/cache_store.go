// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/kvstore/store"
	cslices "github.com/cilium/cilium/pkg/slices"
)

type CacheStore[T store.NamedKey] struct {
	indexer cache.Indexer
}

func NewCacheStore[T store.NamedKey](indexers cache.Indexers) *CacheStore[T] {
	return &CacheStore[T]{
		indexer: cache.NewIndexer(func(obj any) (string, error) {
			return obj.(T).GetKeyName(), nil
		}, indexers),
	}
}

func (s *CacheStore[T]) Get(obj T) (item T, exists bool, err error) {
	var itemAny any
	itemAny, exists, err = s.indexer.Get(obj)
	if exists {
		item = itemAny.(T)
	}
	return
}

func (s *CacheStore[T]) GetByKey(key string) (item T, exists bool, err error) {
	var itemAny any
	itemAny, exists, err = s.indexer.GetByKey(key)
	if exists {
		item = itemAny.(T)
	}
	return
}

func (s *CacheStore[T]) ByIndex(indexName, indexedValue string) ([]T, error) {
	items, err := s.indexer.ByIndex(indexName, indexedValue)
	if err != nil {
		return nil, err
	}
	return cslices.Map(items, func(item any) T {
		return item.(T)
	}), nil
}

func (s *CacheStore[T]) Update(obj T) error {
	return s.indexer.Update(obj)
}

func (s *CacheStore[T]) Delete(obj T) error {
	return s.indexer.Delete(obj)
}
