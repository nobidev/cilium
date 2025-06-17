CREATE TABLE IF NOT EXISTS connections
(
    `id` UUID,

    -- metadata
    `meta/inserted` DateTime64(9, 'UTC') Codec(DoubleDelta, LZ4),
    `ingestion/name` String, -- name of ingestion log event

    `emitter` UInt8,
    `window_start` DateTime64(9, 'UTC') Codec(DoubleDelta, LZ4),
    `window_end` DateTime64(9, 'UTC') Codec(DoubleDelta, LZ4),

    -- source vertex
    `source/family` UInt8, -- corresponds to the proto ID of the vertex family
    -- kubernetes family source vertex
    `source/kubernetes/uid` String,
    `source/kubernetes/resource_kind` UInt8,
    `source/kubernetes/resource_version` String,
    `source/kubernetes/resource_name` String,
    `source/kubernetes/cluster_name` LowCardinality(String),
    `source/kubernetes/namespace` LowCardinality(String),
    `source/kubernetes/node_name` String,
    `source/kubernetes/pod_name` String,
    `source/kubernetes/container_name` String,
    `source/kubernetes/service_kind` UInt8,
    `source/kubernetes/workload_kind` UInt8,
    `source/kubernetes/ipv4` IPv4,
    `source/kubernetes/ipv6` IPv6,
    `source/kubernetes/application_model_uuid` UUID,
    -- network device family source vertex
    `source/network_device/name` String,
    -- world entity family source vertex
    `source/world_entity/dns_name` String,
    `source/world_entity/cidr_block` String,

    -- destination vertex
    `destination/family` UInt8, -- corresponds to the proto ID of the vertex family
    -- kubernetes family destination vertex
    `destination/kubernetes/uid` String,
    `destination/kubernetes/resource_kind` UInt8,
    `destination/kubernetes/resource_version` String,
    `destination/kubernetes/resource_name` String,
    `destination/kubernetes/cluster_name` LowCardinality(String),
    `destination/kubernetes/namespace` LowCardinality(String),
    `destination/kubernetes/node_name` String,
    `destination/kubernetes/pod_name` String,
    `destination/kubernetes/container_name` String,
    `destination/kubernetes/service_kind` UInt8,
    `destination/kubernetes/workload_kind` UInt8,
    `destination/kubernetes/ipv4` IPv4,
    `destination/kubernetes/ipv6` IPv6,
    `destination/kubernetes/application_model_uuid` UUID,
    -- network device family destination vertex
    `destination/network_device/name` String,
    -- world entity family source vertex
    `destination/world_entity/dns_name` String,
    `destination/world_entity/cidr_block` String,

    -- edge
    `link/type` UInt8, -- corresponds to the proto ID of the edge type
    -- network telemetry edge
    `link/network_telemetry/tx_packets` UInt64,
    `link/network_telemetry/tx_bytes` UInt64,
    `link/network_telemetry/tx_drops` UInt64,
    `link/network_telemetry/rx_packets` UInt64,
    `link/network_telemetry/rx_bytes` UInt64,
    `link/network_telemetry/rx_drops` UInt64,
    -- routing telemetry edge
    `link/routing_telemetry/forwarded_count` UInt64,
    `link/routing_telemetry/dropped_count` UInt64,
    `link/routing_telemetry/error_count` UInt64,
    `link/routing_telemetry/audit_count` UInt64,
    `link/routing_telemetry/redirected_count` UInt64,
    `link/routing_telemetry/traced_count` UInt64,
    `link/routing_telemetry/translated_count` UInt64,
)
ENGINE = ReplacingMergeTree()
PRIMARY KEY (
    `link/type`,
    `source/family`,
    `destination/family`,
    `source/kubernetes/cluster_name`,
    `destination/kubernetes/cluster_name`,
    `source/kubernetes/namespace`,
    `destination/kubernetes/namespace`,
    `window_start`,
    `window_end`,
)
ORDER BY (
    `link/type`,
    `source/family`,
    `destination/family`,
    `source/kubernetes/cluster_name`,
    `destination/kubernetes/cluster_name`,
    `source/kubernetes/namespace`,
    `destination/kubernetes/namespace`,
    `window_start`,
    `window_end`,
)
TTL toDateTime(`window_end`) + toIntervalWeek(2)

/*
 * Client query example to draw a graph where vertices are Kubernetes clusters
 * and edges are of type network telemetry.
 *
 * {
 *   // let's get a graph that will give us network telemetry between clusters
 *   // in a given day
 *   "window_start": "2025-06-11T19:15:00",
 *   "window_end: "2025-06-11T20:15:00",
 *   // we want network telemetry as link data, edge.network_telemetry = 1
 *   "link_type: 1,
 *   // We only care about clusters that actually exchanged some data so use a
 *   // filter on the link.
 *   // We only care about Kubernetes and we want to account for trafic only
 *   // once so we filter by vertex family kubernetes node. 
 *   "filter": "link.network_telemetry.tx_packets > 0 && source.family == 1 && destination.family == 1"
 *   // we want our vertices in the resulting graph to represent all our clusters
 *   "group_by_source: ["source.kubernetes.cluster_name"],
 *   // we only care about cross kubernetes cluster traffic
 *   "group_by_destination: ["destination.kubernetes.cluster_name"]
 * }
 *
 * The client query above would translate to the following SQL query.
 *
 * SELECT
 *   `source/kubernetes/cluster` AS source_cluster,
 *   `destination/kubernetes/cluster` AS destination_cluster,
 *   SUM(`link/network_telemetry/tx_packets`) AS tx_packets,
 *   SUM(`link/network_telemetry/tx_bytes`) AS tx_bytes,
 *   SUM(`link/network_telemetry/tx_drops`) AS tx_drops,
 *   SUM(`link/network_telemetry/rx_packets`) AS rx_packets,
 *   SUM(`link/network_telemetry/rx_bytes`) AS rx_bytes,
 *   SUM(`link/network_telemetry/rx_drops`) AS rx_drops
 * FROM connections
 * WHERE `link/type` == 1
 * AND `link/network_telemetry/tx_packets` > 0
 * AND `window_start` >= toDateTime64('2025-06-11 19:15:00', 9, 'UTC')
 * AND `window_end` <= toDateTime64('2025-06-11 20:15:00', 9, 'UTC')
 * AND `source/family` == 1
 * AND `destination/family` == 1
 * GROUP BY
 *   `source/kubernetes/cluster_name` AS source_cluster,
 *   `destination/kubernetes/cluster_name` AS destination_cluster
 *
 * Which gives us the following result
 * note: I only manually added 3 rows and didn't fill all columns :)
 *
 * Row 1:
 * ──────
 * source_cluster:      df-hubble-dev-ce-01
 * destination_cluster: df-tetragon-dev-ce-01
 * tx_packets:          999988812 -- 999.99 million
 * tx_bytes:            0
 * tx_drops:            0
 * rx_packets:          0
 * rx_bytes:            0
 * rx_drops:            0
 *
 * Row 2:
 * ──────
 * source_cluster:      df-hubble-demo-ce-01
 * destination_cluster: df-hubble-dev-ce-01
 * tx_packets:          234453456 -- 234.45 million
 * tx_bytes:            0
 * tx_drops:            0
 * rx_packets:          0
 * rx_bytes:            0
 * rx_drops:            0
 *
 * Row 3:
 * ──────
 * source_cluster:      df-hubble-dev-ce-01
 * destination_cluster: df-hubble-demo-ce-01
 * tx_packets:          1111243455 -- 1.11 billion
 * tx_bytes:            0
 * tx_drops:            0
 * rx_packets:          0
 * rx_bytes:            0
 * rx_drops:            0
 *
 * And we return it as follows to the client:
 *
 * [
 *   {
 *     "link": {
 *       "tx_packets": 999988812,
 *       "tx_bytes": 0,
 *       "tx_drops": 0,
 *       "rx_packets": 0,
 *       "rx_bytes": 0,
 *       "rx_drops": 0
 *     },
 *     "source_fields": [
 *       "kubernetes.cluster_name": "df-hubble-dev-ce-01",
 *     ],
 *     "destination_fields": [
 *       "kubernetes.cluster_name": "df-tetragon-dev-ce-01",
 *     ]
 *   },
 *   {
 *     "link": {
 *       "tx_packets": 234453456,
 *       "tx_bytes": 0,
 *       "tx_drops": 0,
 *       "rx_packets": 0,
 *       "rx_bytes": 0,
 *       "rx_drops": 0
 *     },
 *     "source_fields": [
 *       "kubernetes.cluster_name": "df-hubble-demo-ce-01",
 *     ],
 *     "destination_fields": [
 *       "kubernetes.cluster_name": "df-hubble-dev-ce-01",
 *     ]
 *   },
 *   {
 *     "link": {
 *       "tx_packets": 1111243455,
 *       "tx_bytes": 0,
 *       "tx_drops": 0,
 *       "rx_packets": 0,
 *       "rx_bytes": 0,
 *       "rx_drops": 0
 *     },
 *     "source_fields": [
 *       "kubernetes.cluster_name": "df-hubble-dev-ce-01",
 *     ],
 *     "destination_fields": [
 *       "kubernetes.cluster_name": "df-hubble-demo-ce-01",
 *     ]
 *   },
 * ]
 */
