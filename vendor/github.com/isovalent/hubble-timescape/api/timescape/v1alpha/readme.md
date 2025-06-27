# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [timescape/v1alpha/ingester.proto](#timescape_v1alpha_ingester-proto)
    - [IngestRequest](#timescape-v1alpha-IngestRequest)
    - [IngestResponse](#timescape-v1alpha-IngestResponse)
  
    - [IngesterService](#timescape-v1alpha-IngesterService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="timescape_v1alpha_ingester-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## timescape/v1alpha/ingester.proto



<a name="timescape-v1alpha-IngestRequest"></a>

### IngestRequest
IngestRequest is the request message for the Ingest rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| flow | [flow.Flow](#flow-Flow) |  | Flow is the flow data to be ingested. |






<a name="timescape-v1alpha-IngestResponse"></a>

### IngestResponse
IngestResponse is the response message for the Ingest rpc call.





 

 

 


<a name="timescape-v1alpha-IngesterService"></a>

### IngesterService
IngesterService is a service that allows for ingestion of external data
for Timescape.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Ingest | [IngestRequest](#timescape-v1alpha-IngestRequest) stream | [IngestResponse](#timescape-v1alpha-IngestResponse) | Ingest ingests data into Timescape. |

 



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

