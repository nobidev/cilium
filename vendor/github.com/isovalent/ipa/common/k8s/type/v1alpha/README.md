# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [common/k8s/type/v1alpha/resource.proto](#common_k8s_type_v1alpha_resource-proto)
    - [ResourceKind](#common-k8s-type-v1alpha-ResourceKind)
  
- [common/k8s/type/v1alpha/service.proto](#common_k8s_type_v1alpha_service-proto)
    - [ServiceKind](#common-k8s-type-v1alpha-ServiceKind)
  
- [common/k8s/type/v1alpha/workload.proto](#common_k8s_type_v1alpha_workload-proto)
    - [WorkloadKind](#common-k8s-type-v1alpha-WorkloadKind)
  
- [Scalar Value Types](#scalar-value-types)



<a name="common_k8s_type_v1alpha_resource-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## common/k8s/type/v1alpha/resource.proto


 


<a name="common-k8s-type-v1alpha-ResourceKind"></a>

### ResourceKind
ResourceKind represents the various Kubernetes resources types.

| Name | Number | Description |
| ---- | ------ | ----------- |
| RESOURCE_KIND_UNSPECIFIED | 0 |  |
| RESOURCE_KIND_WORKLOAD | 1 |  |
| RESOURCE_KIND_SERVICE | 2 |  |
| RESOURCE_KIND_CONFIG | 3 |  |
| RESOURCE_KIND_STORAGE | 4 |  |
| RESOURCE_KIND_AUTHENTICATION | 5 |  |
| RESOURCE_KIND_AUTHORIZATION | 6 |  |
| RESOURCE_KIND_POLICY | 7 |  |
| RESOURCE_KIND_EXTEND | 8 |  |
| RESOURCE_KIND_CLUSTER | 9 |  |


 

 

 



<a name="common_k8s_type_v1alpha_service-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## common/k8s/type/v1alpha/service.proto


 


<a name="common-k8s-type-v1alpha-ServiceKind"></a>

### ServiceKind
ServiceKind represents the various Kubernetes service types.

| Name | Number | Description |
| ---- | ------ | ----------- |
| SERVICE_KIND_UNSPECIFIED | 0 |  |
| SERVICE_KIND_CLUSTER_IP | 1 |  |
| SERVICE_KIND_NODE_PORT | 2 |  |
| SERVICE_KIND_LOAD_BALANCER | 3 |  |
| SERVICE_KIND_EXTERNAL_NAME | 4 |  |


 

 

 



<a name="common_k8s_type_v1alpha_workload-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## common/k8s/type/v1alpha/workload.proto


 


<a name="common-k8s-type-v1alpha-WorkloadKind"></a>

### WorkloadKind
WorkloadKind represents the various Kubernetes workload types.

| Name | Number | Description |
| ---- | ------ | ----------- |
| WORKLOAD_KIND_UNSPECIFIED | 0 |  |
| WORKLOAD_KIND_POD | 1 |  |
| WORKLOAD_KIND_DEPLOYMENT | 2 |  |
| WORKLOAD_KIND_DAEMONSET | 3 |  |
| WORKLOAD_KIND_STATEFULSET | 4 |  |
| WORKLOAD_KIND_JOB | 5 |  |
| WORKLOAD_KIND_CRONJOB | 6 |  |
| WORKLOAD_KIND_REPLICASET | 7 |  |


 

 

 



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

