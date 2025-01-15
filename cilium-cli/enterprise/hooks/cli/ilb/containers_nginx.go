//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import "context"

type nginxContainer struct {
	dockerContainer
}

// Upload the content to the Nginx server. After calling this function, the
// uploaded content is accessible with the /<filename> path.
func (n *nginxContainer) UploadContent(ctx context.Context, content []byte, filename string) error {
	return n.Copy(ctx, content, filename, "/usr/share/nginx/html")
}
