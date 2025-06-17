# Graph API documentation and overall concepts

The graph API is a protobuf based API that enables data sources to export
connection events that a client can query to render arbitrary graphs.

The graph API can be thought as the spiritual successor to the Hubble v1 API
when it comes to using networking data to draw graph representations of
networking concepts. However, even though the initial use cases for this API
revolve around networking, the API is extensible and can be adapted to any kind
of connection as new `Edge` and `Vertex` types can be added. This aspect of the
API allows rendering almost arbitrary graphs, as long as the underlying data is
provided.

One of the core concept of the graph API is data aggregation. With the concept
of a time window, data can be aggregated at the source that emits connection
events but also at query time to cover different time windows. The use of
aggregation allows to drastically reduce the number of connection log messages
that have to be processed. To enable this property, all of the metadata on the
edge of a connection must be aggregatable by some function, typically `SUM`.

Data emitter such as Hubble and Tetragon MUST emit as many connection log events
per pair of vertices as there are edge types that correspond to the given
connection(s).

Another core concept of the graph API is that while the source of connection
data may be very specific, which allows for database optimizations, the querying
facilities is generic and flexible. In other words, clients may query for
various types of connections using the same query concepts. This property allows
client to render graphs that represent varying data using the same rendering
engine and code.

Properties of vertices MUST be scalar properties as opposed to collections or
more complex types. The reason for this constraint is that arbitrary vertices
may be created by clients by grouping one or more source and destination vertex
attributes. If non-scalar properties have to be represented, they must be
unrolled or flattened out. However, consider that showing too much information
in a graph does not provide value. Consider add unique identifiers to the vertex
property that would allow a client to query another data source to obtain more
information regarding a given vertex.
