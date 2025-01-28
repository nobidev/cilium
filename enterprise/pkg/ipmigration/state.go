//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ipmigration

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/spf13/afero"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/defaults"
)

const (
	StateDirectory    = defaults.RuntimePath + "/enterprise/ipmigration"
	TemplateDirectory = StateDirectory + "/templates/by-pod-uid"
)

// endpointTemplates stores models.EndpointChangeRequests (aka "endpoint templates") on disk. It will store all
// submitted endpoint creation requests per K8s pod (e.g. if there are multiple in case of multi-network),
// allows fetching all endpoint templates for a given K8s pod UID, deleting all endpoint templates for a given K8s pod
// UID and pruning the store by only keeping the endpoint templates of live pods.
// The underlying file structure in the state directory (/var/run/cilium/enteprise/ipmigration) looks as follows:
//
//	 templates/
//			by-pod-uid/
//				6fe439e8-b6d6-4bc5-85b6-fb44a9bd2ecc/										(pod UID 6fe..)
//					0364cf03b13749b95e6839af36c0f2fd8554e5a1564eb55ac780550a3bec8474.json   (endpoint template for pod 6fe..)
//				5403f27b-69cc-4a6d-aaf5-3b3eb72dc1a8/										(pod UID 540...)
//					8bddf060fcba16eb18ccbce1ede8ff29aaedfe0aab2e620d05e7793dec265fb3.json	(endpoint template one for pod 540..)
//					e55cbb7998426658c03d3ef9a3ece56c928a003e4bd1ab12716347ba57b13922.json	(endpoint template two for pod 540..)
type endpointTemplates struct {
	fs afero.Fs
}

// persistentEndpointTemplates persists endpoint templates on disk. This is used for production.
func persistentEndpointTemplates() *endpointTemplates {
	return &endpointTemplates{
		fs: afero.NewOsFs(),
	}
}

// ephemeralEndpointTemplates persists endpoints in memory. This is used in unit tests.
func ephemeralEndpointTemplates() *endpointTemplates {
	return &endpointTemplates{
		fs: afero.NewMemMapFs(),
	}
}

// persistEndpointTemplate writes the provided endpoint template to disk. The provided endpoint template must contain
// a valid K8sUID, otherwise an error is returned.
// Persisting the same endpoint template twice is idempotent.
func (e *endpointTemplates) persistEndpointTemplate(ep *models.EndpointChangeRequest) error {
	if ep.K8sUID == "" {
		return fmt.Errorf("cannot persist endpoint template without a k8s UID")
	}

	podStateDir := filepath.Join(TemplateDirectory, ep.K8sUID)
	err := e.fs.MkdirAll(podStateDir, defaults.StateDirRights)
	if err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}

	buf, err := ep.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshalling endpoint change request: %w", err)
	}

	// unique filename
	hash := sha256.Sum256(buf)
	filename := hex.EncodeToString(hash[:]) + ".json"
	err = afero.WriteFile(e.fs, filepath.Join(podStateDir, filename), buf, 0644)
	if err != nil {
		return fmt.Errorf("creating template file %s: %w", filename, err)
	}

	return nil
}

// getEndpointTemplatesForPod returns all endpoint templates for a given K8s Pod UID.
// Returns an error which wraps fs.ErrNotExist if no endpoint templates have been persisted for this pod.
func (e *endpointTemplates) getEndpointTemplatesForPod(uid k8sTypes.UID) ([]*models.EndpointChangeRequest, error) {
	if len(uid) == 0 {
		return nil, errors.New("cannot get endpoint templates for empty pod UID")
	}

	podStateDir := filepath.Join(TemplateDirectory, string(uid))
	files, err := afero.ReadDir(e.fs, podStateDir)
	if err != nil {
		return nil, fmt.Errorf("reading template directory: %w", err)
	}

	epTemplates := make([]*models.EndpointChangeRequest, 0, len(files))
	for _, file := range files {
		var ep models.EndpointChangeRequest
		tmplFile := filepath.Join(podStateDir, file.Name())
		buf, err := afero.ReadFile(e.fs, tmplFile)
		if err != nil {
			return nil, fmt.Errorf("reading template file %q: %w", tmplFile, err)
		}
		err = ep.UnmarshalBinary(buf)
		if err != nil {
			return nil, fmt.Errorf("unmarshalling template file %q: %w", tmplFile, err)
		}

		epTemplates = append(epTemplates, &ep)
	}

	return epTemplates, nil
}

// deleteEndpointTemplatesForPod deletes all endpoint templates associated with the provided K8s pod UID.
// Returns an error which wraps fs.ErrNotExist if no templates were found.
func (e *endpointTemplates) deleteEndpointTemplatesForPod(uid k8sTypes.UID) error {
	podStateDir := filepath.Join(TemplateDirectory, string(uid))
	return e.fs.RemoveAll(podStateDir)
}

// pruneEndpointTemplates removes all endpoint templates for any pods not found in alive.
// Returns the number of successfully pruned pods and an error. This will attempt to continue pruning
// endpoint templates if an error occurs, so pruned can be non-zero even if err contains an error.
func (e *endpointTemplates) pruneEndpointTemplates(alive sets.Set[k8sTypes.UID]) (pruned int, err error) {
	templates, err := afero.ReadDir(e.fs, TemplateDirectory)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil // nothing to do
		}
		return 0, fmt.Errorf("reading template directory: %w", err)
	}

	var allErrors error
	for _, templateDir := range templates {
		uid := templateDir.Name()
		if alive.Has(k8sTypes.UID(uid)) {
			continue // skip deletion
		}

		err = e.deleteEndpointTemplatesForPod(k8sTypes.UID(uid))
		if err != nil {
			allErrors = errors.Join(allErrors, fmt.Errorf("removing template directory %q: %w", uid, err))
		} else {
			pruned++
		}
	}

	return pruned, allErrors
}
