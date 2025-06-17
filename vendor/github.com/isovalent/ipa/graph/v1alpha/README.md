# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [graph/v1alpha/edge.proto](#graph_v1alpha_edge-proto)
    - [Edge](#graph-v1alpha-Edge)
    - [EdgeTypeL7Telemetry](#graph-v1alpha-EdgeTypeL7Telemetry)
    - [EdgeTypeNetworkTelemetry](#graph-v1alpha-EdgeTypeNetworkTelemetry)
    - [EdgeTypeRoutingTelemetry](#graph-v1alpha-EdgeTypeRoutingTelemetry)
  
- [graph/v1alpha/vertex.proto](#graph_v1alpha_vertex-proto)
    - [Vertex](#graph-v1alpha-Vertex)
    - [VertexFamilyKubernetes](#graph-v1alpha-VertexFamilyKubernetes)
    - [VertexFamilyNetworkDevice](#graph-v1alpha-VertexFamilyNetworkDevice)
    - [VertexFamilyWorldEntity](#graph-v1alpha-VertexFamilyWorldEntity)
  
- [graph/v1alpha/connection.proto](#graph_v1alpha_connection-proto)
    - [Connection](#graph-v1alpha-Connection)
    - [ConnectionLog](#graph-v1alpha-ConnectionLog)
  
    - [Emitter](#graph-v1alpha-Emitter)
  
- [graph/v1alpha/service.proto](#graph_v1alpha_service-proto)
    - [ConnectionResponse](#graph-v1alpha-ConnectionResponse)
    - [ConnectionResponse.DestinationFieldsEntry](#graph-v1alpha-ConnectionResponse-DestinationFieldsEntry)
    - [ConnectionResponse.SourceFieldsEntry](#graph-v1alpha-ConnectionResponse-SourceFieldsEntry)
    - [GetConnectionsRequest](#graph-v1alpha-GetConnectionsRequest)
    - [GetConnectionsResponse](#graph-v1alpha-GetConnectionsResponse)
  
    - [GraphService](#graph-v1alpha-GraphService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="graph_v1alpha_edge-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## graph/v1alpha/edge.proto



<a name="graph-v1alpha-Edge"></a>

### Edge
An edge represents aggregatable properties of a given connection.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| network_telemetry | [EdgeTypeNetworkTelemetry](#graph-v1alpha-EdgeTypeNetworkTelemetry) |  |  |
| routing_telemetry | [EdgeTypeRoutingTelemetry](#graph-v1alpha-EdgeTypeRoutingTelemetry) |  |  |
| l7_telemetry | [EdgeTypeL7Telemetry](#graph-v1alpha-EdgeTypeL7Telemetry) |  |  |






<a name="graph-v1alpha-EdgeTypeL7Telemetry"></a>

### EdgeTypeL7Telemetry
EdgeTypeL7Telemetry provides telemetry information regarding a network
connection at the application layer.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| http_requests_total | [uint64](#uint64) |  | http_requests_total is the number of HTTP requests that occurred during the selected time window. In conjunction with http_server_errors_total and http_client_errors_total, one can determine the error rate as a percent of requests that are failing from the total number of requests. One can also measure throughput in terms of HTTP requests per second. |
| http_server_errors_total | [uint64](#uint64) |  | http_server_errors_total is the number of HTTP server errors (5xx) that occurred during the selected time window. |
| http_client_errors_total | [uint64](#uint64) |  | http_client_errors_total is the number of HTTP client errors (4xx) that occurred during the selected time window. |






<a name="graph-v1alpha-EdgeTypeNetworkTelemetry"></a>

### EdgeTypeNetworkTelemetry
EdgeTypeNetworkTelemetry provides telemetry information regarding a network
connection.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| network_transmit_packets_total | [uint64](#uint64) |  | network_transmit_packets_total is the number of packets transferred. |
| network_transmit_bytes_total | [uint64](#uint64) |  | network_transmit_bytes_total is the number of bytes transferred. |
| network_transmit_drop_total | [uint64](#uint64) |  | network_transmit_drop_total is the number of packets dropped during transmission. |
| network_receive_packets_total | [uint64](#uint64) |  | network_receive_packets_total is the number of packets received. |
| network_receive_bytes_total | [uint64](#uint64) |  | network_receive_bytes_total is the number of bytes received. |
| network_receive_drop_total | [uint64](#uint64) |  | network_receive_drop_total is the number of packets that are received but discarded. |






<a name="graph-v1alpha-EdgeTypeRoutingTelemetry"></a>

### EdgeTypeRoutingTelemetry
EdgeTypeRoutingTelemetry provides telemetry information regarding routing
decisions.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| routing_forwarded_total | [uint64](#uint64) |  | routing_forwarded_total is the number of network flows that have been forwarded to the next processing entity. |
| routing_dropped_total | [uint64](#uint64) |  | routing_dropped_total is the number of network flows that have been dropped. Reasons for dropping data may be due to a malformed packet, rejection by a network policy, etc. |
| routing_error_total | [uint64](#uint64) |  | routing_error_total is the number of flows where an error occurred during processing. |
| routing_audit_total | [uint64](#uint64) |  | routing_audit_total is the number of times a flow would have been dropped if a network policy that applies to it was enforced. |
| routing_redirected_total | [uint64](#uint64) |  | routing_redirected_total is the number of flows which have been redirected, for instance to a local proxy. |
| routing_traced_total | [uint64](#uint64) |  | routing_traced_total is the number of flows that have been observed at a trace point. |
| routing_translated_total | [uint64](#uint64) |  | routing_translated_total is the number of flows where are address has been translated. |





 

 

 

 



<a name="graph_v1alpha_vertex-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## graph/v1alpha/vertex.proto



<a name="graph-v1alpha-Vertex"></a>

### Vertex
A vertex represents a set of properties of a connection source or
destination.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| kubernetes | [VertexFamilyKubernetes](#graph-v1alpha-VertexFamilyKubernetes) |  |  |
| network_device | [VertexFamilyNetworkDevice](#graph-v1alpha-VertexFamilyNetworkDevice) |  |  |
| world_entity | [VertexFamilyWorldEntity](#graph-v1alpha-VertexFamilyWorldEntity) |  |  |






<a name="graph-v1alpha-VertexFamilyKubernetes"></a>

### VertexFamilyKubernetes
VertexFamilyKubernetes represent vertex properties that are related to a
Kubernetes context.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uid | [string](#string) |  | UID is the unique in time and space value of the Kubernetes object. |
| resource_kind | [common.k8s.type.v1alpha.ResourceKind](#common-k8s-type-v1alpha-ResourceKind) |  | resource_kind defines the type of Kubernetes resource. |
| resource_version | [string](#string) |  | resource_version is an opaque value that represents the internal version of the Kubernetes object. |
| resource_name | [string](#string) |  | resource_name is the name of the Kubernetes object which is unique within a namespace. |
| cluster_name | [string](#string) |  | cluster_name is the name of the Kubernetes cluster. |
| namespace | [string](#string) |  | namespace is the space within which each resource name is unique. |
| node_name | [string](#string) |  | node_name is the name of the Kubernetes node. |
| pod_name | [string](#string) |  | pod_name is the name of the Kubernetes pod. |
| container_name | [string](#string) |  | container_name is the name of the container. |
| service_kind | [common.k8s.type.v1alpha.ServiceKind](#common-k8s-type-v1alpha-ServiceKind) |  | service_kind represents the type of the Kubernetes service. |
| workload_kind | [common.k8s.type.v1alpha.WorkloadKind](#common-k8s-type-v1alpha-WorkloadKind) |  | workload_kind represents the type of the Kubernetes workload. |
| ip | [string](#string) |  | ip is a network address that can be associated with the Kubernetes resource and the connection. |
| port | [uint32](#uint32) |  | port is the network port associated with the ip address. |
| application_model_uuid | [string](#string) |  | application_model_uuid is a unique identifier that identifies the application model associated with the Kubernetes resource. |






<a name="graph-v1alpha-VertexFamilyNetworkDevice"></a>

### VertexFamilyNetworkDevice
VertexFamilyNetworkDevice represents vertex properties that are related to a
network device.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | name is the name of the network device. |
| ip | [string](#string) |  | ip is a network address that can be associated with the network device and the connection. |
| port | [uint32](#uint32) |  | port is the network port associated with the ip address. |






<a name="graph-v1alpha-VertexFamilyWorldEntity"></a>

### VertexFamilyWorldEntity
VertexFamilyWorldEntity represents a broad set of network elements outside
of a specific network boundary.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| dns_name | [string](#string) |  | dns_name is the DNS name that can be associated with the world entity. |
| ip | [string](#string) |  | ip is a network address that can be associated with the world entity and the connection. |
| port | [uint32](#uint32) |  | port is the network port associated with the ip address. |





 

 

 

 



<a name="graph_v1alpha_connection-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## graph/v1alpha/connection.proto



<a name="graph-v1alpha-Connection"></a>

### Connection
A connection is a simple directed graph where an edge links two vertices in
one direction.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source | [Vertex](#graph-v1alpha-Vertex) |  | Source defines properties of the vertex at the emitting side of the connection. |
| destination | [Vertex](#graph-v1alpha-Vertex) |  | Source defines properties of the vertex at the receiving side of the connection. |
| links | [Edge](#graph-v1alpha-Edge) | repeated | Links define properties of the edges that link the two vertices.

There MUST be at least one link between the source and destination vertices.

If more than one link is provided, their type MUST be different. In other words, links MUST be a set of at least one element where every element in the set is of a different edge type. |






<a name="graph-v1alpha-ConnectionLog"></a>

### ConnectionLog
A connection log is a message that a source emits periodically and which
provides information about connections.

Emitters SHOULD NOT re-emit ConnectionLog events.
ConnectionLog events SHOULD NOT have overlapping time windows.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| emitter | [Emitter](#graph-v1alpha-Emitter) |  | An emitter is the source that observes connection information. The emitter typically observes data at the source of the connection. |
| window_start | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Window start is the time at which the emitter started collecting information regarding the observed connections. |
| window_end | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Window end is the time at which the emitter stopped collecting information regarding the observed connections. |
| connections | [Connection](#graph-v1alpha-Connection) | repeated | Connections is a list of all connections that were tracked during the given time window. |





 


<a name="graph-v1alpha-Emitter"></a>

### Emitter
Emitter is a list of all known connection log data sources.

| Name | Number | Description |
| ---- | ------ | ----------- |
| EMITTER_UNSPECIFIED | 0 | The source of the data is unspecified. |
| EMITTER_HUBBLE | 1 | The source of the data is Hubble. |
| EMITTER_TETRAGON | 2 | The source of the data is Tetragon. |


 

 

 



<a name="graph_v1alpha_service-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## graph/v1alpha/service.proto



<a name="graph-v1alpha-ConnectionResponse"></a>

### ConnectionResponse
ConnectionResponse represents a specific connection.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| link | [Edge](#graph-v1alpha-Edge) |  | Link may provide aggregated information regarding the connection. |
| source_fields | [ConnectionResponse.SourceFieldsEntry](#graph-v1alpha-ConnectionResponse-SourceFieldsEntry) | repeated | Source fields are properties that correspond to the vertex field keys specified in the group_by_source field of the query. Example: { &#34;cluster_name&#34;: &#34;df-hubble-dev-ce-01&#34;, &#34;node_name&#34;: &#34;ip-10-1-5-110.us-west-2.compute.internal&#34; } |
| destination_fields | [ConnectionResponse.DestinationFieldsEntry](#graph-v1alpha-ConnectionResponse-DestinationFieldsEntry) | repeated | Destination fields are properties that correspond to the vertex field keys specified in the group_by_destination field of the query. Example: { &#34;namespace&#34;: &#34;kube-system&#34;, } |






<a name="graph-v1alpha-ConnectionResponse-DestinationFieldsEntry"></a>

### ConnectionResponse.DestinationFieldsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="graph-v1alpha-ConnectionResponse-SourceFieldsEntry"></a>

### ConnectionResponse.SourceFieldsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="graph-v1alpha-GetConnectionsRequest"></a>

### GetConnectionsRequest
GetConnectionsRequest allows for specifying the type of connections that
should be returned.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| window_start | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Window start is the start time of the time window. A time window SHOULD be provided to limit the number of connections returned. |
| window_end | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Window end is the end time of the time window. A time window SHOULD be provided to limit the number of connections returned. |
| link_type | [uint32](#uint32) |  | The link type MUST be provided. It corresponds to the protobuf tag of the desired edge type of the link. |
| filter | [string](#string) |  | A CEL expression MAY be used to filter connections.

The filtering expression may use the `link` (type: Edge), `source` and `destination` variables (type: Vertex). Example: has(link.network_telemetry) &amp;&amp; link.network_telemetry.tx_packets &gt; 0 &amp;&amp; has(source.kubernetes) &amp;&amp; source.kubernetes.cluster_name == &#34;df-hubble-demo-ce-01&#34; &amp;&amp; has(destination.kubernetes) &amp;&amp; destination.kubernetes.cluster_name = &#34;df-hubble-dev-ce-01&#34; |
| group_by_source | [string](#string) | repeated | Field keys by which the source vertex should be grouped. At least one field MUST be provided. Example: [&#34;source.kubernetes.cluster_name&#34;, &#34;source.kubernetes.node_name&#34;] |
| group_by_destination | [string](#string) | repeated | Field keys by which the destination vertex should be grouped. At least one field MUST be provided. Example: [&#34;destination.kubernetes.cluster_name&#34;, &#34;destination.kubernetes.node_name&#34;] |






<a name="graph-v1alpha-GetConnectionsResponse"></a>

### GetConnectionsResponse
GetConnectionsResponse is the response provided by the GetConnections endpoint.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| connections | [ConnectionResponse](#graph-v1alpha-ConnectionResponse) | repeated | Connections is a list of all the connections that match the request criteria. There should be only one connection per unique vertex-edge-vertex. In other words, field values and time window are aggregated. |





 

 

 


<a name="graph-v1alpha-GraphService"></a>

### GraphService
The graph services allows querying connections information that are
typically useful to render a graph visualization.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetConnections | [GetConnectionsRequest](#graph-v1alpha-GetConnectionsRequest) | [GetConnectionsResponse](#graph-v1alpha-GetConnectionsResponse) | GetConnections returns a set of connections that match the query criteria. |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

