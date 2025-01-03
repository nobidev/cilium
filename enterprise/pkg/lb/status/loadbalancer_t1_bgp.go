// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
)

// getBGPRoutes gets BGP routes from all T1 cilium agent pods.
func (s *LoadbalancerClient) getBGPRoutes(ctx context.Context) (map[string][]*models.BgpRoute, error) {
	res, err := s.fetchBGPRoutesConcurrently(ctx)
	if err != nil {
		if len(res) == 0 {
			// no results retrieved - just return the error
			return nil, err
		}
		// print the errors, but continue with printing results
		fmt.Fprintf(os.Stderr, "Errors by retrieving routes: %v\n\n", err)
	}

	return res, nil
}

// getBGPPeersFromCRD gets BGP peers per LB svc from IsovalentBGPClusterConfigs.
func (s *LoadbalancerClient) getBGPPeersFromCRD(ctx context.Context) (map[string]map[string]struct{}, error) {
	bgpPeers := map[string]map[string]struct{}{} // svc => map[peerAddr-peerASN]

	cfgs, err := s.client.CiliumClientset.IsovalentV1alpha1().IsovalentBGPClusterConfigs().List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list IsovalentBGPClusterConfigs: %w", err)
	}

	for _, cfg := range cfgs.Items {
		for _, instances := range cfg.Spec.BGPInstances {
			for _, peer := range instances.Peers {
				svcName := peer.PeerConfigRef.Name
				if _, ok := bgpPeers[svcName]; !ok {
					bgpPeers[svcName] = map[string]struct{}{}
				}
				bgpPeers[svcName][fmt.Sprintf("%s-%d", *peer.PeerAddress, *peer.PeerASN)] = struct{}{}
			}
		}
	}

	return bgpPeers, nil
}

func (s *LoadbalancerClient) fetchBGPRoutesConcurrently(ctx context.Context) (map[string][]*models.BgpRoute, error) {
	allFetchedData := make(map[string][]*models.BgpRoute)

	// res contains data returned from cilium pod
	type res struct {
		nodeName string
		data     []*models.BgpRoute
		err      error
	}
	resCh := make(chan res)

	var wg sync.WaitGroup

	// max number of concurrent go routines will be number of cilium agent pods
	wg.Add(len(s.t1AgentPods))

	// compute the command for fetching the routes from a cilium pod
	fetchCmd := []string{"cilium-dbg", "bgp", "routes"}
	fetchCmd = append(fetchCmd, "advertised")
	fetchCmd = append(fetchCmd, "-o", "json")

	// concurrently fetch routes from each T1 cilium pod
	for _, pod := range s.t1AgentPods {
		go func(ctx context.Context, pod *Pod) {
			defer wg.Done()

			routes, err := s.fetchBGPRoutesFromPod(ctx, fetchCmd, pod)
			resCh <- res{
				nodeName: pod.NodeName,
				data:     routes,
				err:      err,
			}
		}(ctx, pod)
	}

	// close resCh when data from all nodes is collected
	go func() {
		wg.Wait()
		close(resCh)
	}()

	// read from the channel till it is closed.
	// on error, store error and continue to next node.
	var err error
	for fetchedData := range resCh {
		if fetchedData.err != nil {
			err = errors.Join(err, fetchedData.err)
		} else {
			allFetchedData[fetchedData.nodeName] = fetchedData.data
		}
	}

	return allFetchedData, err
}

func (s *LoadbalancerClient) fetchBGPRoutesFromPod(ctx context.Context, fetchCmd []string, pod *Pod) ([]*models.BgpRoute, error) {
	output, errOutput, err := s.client.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, "cilium-agent", fetchCmd)
	if err != nil {
		var errStr string
		if errOutput.String() != "" {
			errStr = strings.TrimSpace(errOutput.String())
		} else {
			errStr = err.Error()
		}
		return nil, fmt.Errorf("failed to fetch bgp state from %s: (%s)", pod.Name, errStr)
	}

	bgpRoutes := make([]*models.BgpRoute, 0)

	err = json.Unmarshal(output.Bytes(), &bgpRoutes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal bgp routes from %s: %w", pod.Name, err)
	}

	return bgpRoutes, nil
}

// getBGPPeers gets BGP peers from all T1 cilium agent pods.
func (s *LoadbalancerClient) getBGPPeers(ctx context.Context) (map[string][]*models.BgpPeer, error) {
	res, err := s.fetchBGPPeersConcurrently(ctx)
	if err != nil {
		if len(res) == 0 {
			// no results retrieved - just return the error
			return nil, err
		}
		// print the errors, but continue with printing results
		fmt.Fprintf(os.Stderr, "Errors by retrieving peers: %v\n\n", err)
	}

	return res, nil
}

func (s *LoadbalancerClient) fetchBGPPeersConcurrently(ctx context.Context) (map[string][]*models.BgpPeer, error) {
	allFetchedData := make(map[string][]*models.BgpPeer)

	// res contains data returned from cilium pod
	type res struct {
		nodeName string
		data     []*models.BgpPeer
		err      error
	}
	resCh := make(chan res)

	var wg sync.WaitGroup

	// max number of concurrent go routines will be number of cilium agent pods
	wg.Add(len(s.t1AgentPods))

	// compute the command for fetching the routes from a cilium pod
	fetchCmd := []string{"cilium-dbg", "bgp", "peers"}
	fetchCmd = append(fetchCmd, "-o", "json")

	// concurrently fetch peers from each T1 cilium pod
	for _, pod := range s.t1AgentPods {
		go func(ctx context.Context, pod *Pod) {
			defer wg.Done()

			peers, err := s.fetchBGPPeersFromPod(ctx, fetchCmd, pod)
			resCh <- res{
				nodeName: pod.NodeName,
				data:     peers,
				err:      err,
			}
		}(ctx, pod)
	}

	// close resCh when data from all nodes is collected
	go func() {
		wg.Wait()
		close(resCh)
	}()

	// read from the channel till it is closed.
	// on error, store error and continue to next node.
	var err error
	for fetchedData := range resCh {
		if fetchedData.err != nil {
			err = errors.Join(err, fetchedData.err)
		} else {
			allFetchedData[fetchedData.nodeName] = fetchedData.data
		}
	}

	return allFetchedData, err
}

func (s *LoadbalancerClient) fetchBGPPeersFromPod(ctx context.Context, fetchCmd []string, pod *Pod) ([]*models.BgpPeer, error) {
	output, errOutput, err := s.client.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, "cilium-agent", fetchCmd)
	if err != nil {
		var errStr string
		if errOutput.String() != "" {
			errStr = strings.TrimSpace(errOutput.String())
		} else {
			errStr = err.Error()
		}
		return nil, fmt.Errorf("failed to fetch bgp state from %s: (%s)", pod.Name, errStr)
	}

	bgpPeers := make([]*models.BgpPeer, 0)

	err = json.Unmarshal(output.Bytes(), &bgpPeers)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal bgp peers from %s: %w", pod.Name, err)
	}

	return bgpPeers, nil
}
