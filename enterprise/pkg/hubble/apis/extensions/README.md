# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [extensions/flow.proto](#extensions_flow-proto)
    - [FlowExtension](#hubble_extensions-v1-FlowExtension)
    - [PrivateNetworkEndpoint](#hubble_extensions-v1-PrivateNetworkEndpoint)
    - [PrivateNetworkFlowExtension](#hubble_extensions-v1-PrivateNetworkFlowExtension)
  
    - [PrivateNetworkEndpointType](#hubble_extensions-v1-PrivateNetworkEndpointType)
  
- [Scalar Value Types](#scalar-value-types)



<a name="extensions_flow-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## extensions/flow.proto



<a name="hubble_extensions-v1-FlowExtension"></a>

### FlowExtension
FlowExtension is the INK flow extension


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| private_networks | [PrivateNetworkFlowExtension](#hubble_extensions-v1-PrivateNetworkFlowExtension) |  | private_networks contains Private Networks related information |






<a name="hubble_extensions-v1-PrivateNetworkEndpoint"></a>

### PrivateNetworkEndpoint
PrivateNetworkEndpoint contains Private Networks related information for an endpoint


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [PrivateNetworkEndpointType](#hubble_extensions-v1-PrivateNetworkEndpointType) |  | type is the endpoint type. Valid types are ENDPOINT: for Cilium internal endpoints EXTERNAL_ENDPOINT: for &#34;external endpoints&#34; defined by PrivateNetworkExternalEndpoint resources UNMANAGED: for destinations outside of the cluster |
| cilium_endpoint_ip | [string](#string) |  | cilium_endpoint_ip is the Cilium internal IP for the endpoint. Only set for ENDPOINT and EXTERNAL_ENDPOINT types |
| network_id | [uint32](#uint32) |  | network_id is the reported node local ID of the network this endpoint is in |
| network_name | [string](#string) |  | network_name is the name of the network this endpoint is in. Only set for ENDPOINT and EXTERNAL_ENDPOINT types |
| subnet_name | [string](#string) |  | subnet_name is the name of the subnet this endpoint is in. Only set for ENDPOINT and EXTERNAL_ENDPOINT types |






<a name="hubble_extensions-v1-PrivateNetworkFlowExtension"></a>

### PrivateNetworkFlowExtension
PrivateNetworkFlowExtension contains Private Networks related flow extensions


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source | [PrivateNetworkEndpoint](#hubble_extensions-v1-PrivateNetworkEndpoint) |  | source contains Private Networks related information for the source endpoint |
| destination | [PrivateNetworkEndpoint](#hubble_extensions-v1-PrivateNetworkEndpoint) |  | destination contains Private Networks related information for the destination endpoint |





 


<a name="hubble_extensions-v1-PrivateNetworkEndpointType"></a>

### PrivateNetworkEndpointType
PrivateNetworkEndpointType is the type of a PrivateNetworkEndpoint

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN | 0 |  |
| ENDPOINT | 1 | ENDPOINT is the type of Cilium internal endpoints |
| EXTERNAL_ENDPOINT | 2 | EXTERNAL_ENDPOINT is the type of &#34;external endpoints&#34; defined by PrivateNetworkExternalEndpoint resources |
| UNMANAGED | 3 | UNMANAGED indicates that the endpoint is not a Cilium managed endpoint, but a destination outside of the cluster |


 

 

 



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

