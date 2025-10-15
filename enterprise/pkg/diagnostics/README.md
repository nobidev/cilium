# Cilium Enterprise self-diagnostics

Diagnostics provide a way for Isovalent products to report problems to users
for troubleshooting and to proactively correct issues through early alerts.

The diagnostics feature consists of:
- This `diagnostics` package containing tooling for Cilium to register and evaluate
  diagnostic conditions and controller periodically exporting current status to
  `status.log`
- `enterprise/daemon/diagnostics.go` defining conditions for OSS features
- The `system_status` protocol in `isovalent/ipa` defines the messages for reporting
  diagnostics as status updates.
- System status ingestion, gRPC service and UI in Timescape for viewing diagnostics.
- `cilium diagnostics` command for inspecting agent diagnostics with Enterprise cilium-cli
- The diagnostics `cilium connectivity test` to fail tests if diagnostics conditions fail.
- The diagnostics sysdump hook to add `diagnostics.txt` to sysdumps.

See Feature narrative for a high level description:
https://docs.google.com/document/d/1yS2i8UfjE0LlxLAWwU-HQUsvUxcShmeLsh95W5IuY6s

System status protocol:
https://github.com/isovalent/ipa/blob/main/system_status/v1alpha/system_status.proto

Early design document (now out of date):

https://docs.google.com/document/d/1iDMa3cih-M-gkbG22l1V4h-kODxTwMoGSsZGQULyWpg

```
  <condition X>   <condition Y>
       |         / (evaluate)
  <cilium-agent>
       | (append system_status_update every 5 minutes)
       v
   status.log
       | (fluentd watches)
       v
 (object store)
       |
       v
<timescape ingest>
       | (INSERT INTO system_status_updates ...)
       v
 <clickhouse DB>
       |
       v
 <timescape serve>
       | (gRPC)
       v
<timescape UI: system status>
       |
       v
    (USER)   
```

## Defining diagnostics

Diagnostics are added via the `diagnostics.Registry`, for example:

```go
  cell.Invoke(func(reg *diagnostics.Registry, foo *FooController)) {
    reg.Register(
      diagnostics.Condition{
        ID: "example_metric",
        SubSystem: "Example",
        Description: "This is an example condition based on metrics",
        Evaluator: evalExampleMetric,
      },
      diagnostics.Condition{
        ID: "example_internal",
        SubSystem: "Example",
        Description: "This is an example condition based on internal state",
        Evaluator: foo.evalExampleInternal,
      },
    )
  }
  func evalExampleMetric(env diagnostics.Environment) (diagnostics.Message, diagnostics.Severity) {
  	stats, err := env.Histogram("cilium_example_histogram", nil)
  	if err != nil {
  		return err.Error(), diagnostics.OK
  	}
  	if stats.Avg_24h > 0.0 && stats.Avg_Latest > 3*stats.Avg_24h {
  		return fmt.Sprintf("average latency %.1fs is >3x the 24 hour average of %.1fs",
  			stats.Avg_Latest, stats.Avg_24h), diagnostics.Minor
  	}
  	return fmt.Sprintf("%.2fs OK", stats.Avg_Latest), diagnostics.OK
  }

  func (foo *FooController) evalExampleInternal(env diagnostics.Environment) (diagnostics.Message, diagnostics.Severity) {
    if foo.IsHealty() {
      return "Healthy", diagnostics.OK
    }
    return "Unhealthy", diagnostics.Minor
  }
```

The `Register` method can be called at any time and diagnostics can be unregistered
with `Unregister`. The registered diagnostics are stored in StateDB table, which
can be inspected with `db/show diagnostics`.

The `diagnostics.Environment` interface provides access to metrics and allows
sampling of metrics from the past 24 hours.

A controller runs periodically to invoke each conditions evaluation function
and to produce a system status update message that Timescape will ingest.

See also `enterprise/daemon/diagnostics.go` for examples of existing diagnostics.
Note that diagnostics for enterprise features should be located in their respective
cells and `enterprise/daemon/diagnostics.go` is meant only for diagnostics of OSS
features.

## Inspecting diagnostics

The diagnostics can be inspected in Timescape's system status view or
with Cilium CLI:

```shell
$ cilium diagnostics
=== Summary ===

Nodes healthy:          100%    [2/2]
Conditions passing:     100%    [6/6]
```

The diagnostics of a single node can be checked in Cilium Shell:

```shell
$ kubectl exec -it -n kube-system ds/cilium -- cilium-dbg shell -- db/show diagnostics
ID                      Total   Failed   Latest                                                      LastFailure                                               Evaluator
endpoint_regeneration   1       0        Succeeded 2m29s ago: 0.00s OK                               <none>                                                    main.evalEndpointRegeneration (.../enterprise/daemon/diagnostics.go:85)
hive_degraded_modules   1       1        Failed 2m29s ago (DEBUG): Degraded modules: dummy.dummy     Failed 2m29s ago (DEBUG): Degraded modules: dummy.dummy   main.registerConditions.evalHiveHealth.func1 (.../enterprise/daemon/diagnostics.go:102)
statedb                 1       0        Succeeded 2m29s ago: WriteTxn OK (max 0.0s), Graveyard OK   <none>                                                    main.registerConditions.evalStateDB.func2 (.../enterprise/daemon/diagnostics.go:117)
```

The status.log can also be inspected:

```shell
$ kubectl exec -it -n kube-system ds/cilium -- cat /var/run/cilium/hubble/status.log
{"system_status":{"metadata":{"system":{"name":"cilium-agent","version":"1.19.0-dev"},"conditions":[{"condition_id":"endpoint_regeneration","subsystem":"Endpoint","description":"Endpoint regeneration is taking longer than expected"},{"condition_id":"hive_degraded_modules","subsystem":"Hive","description":"One or more agent module is reporting degraded status"},{"condition_id":"statedb","subsystem":"StateDB","description":"StateDB metrics indicate a potentially problematic access patterns"}]}},"time":"2025-10-15T15:05:54.885647455Z","node_name":"kind-worker"}
{"system_status":{"time":"2025-10-15T15:05:54.891177812Z","status":{"cluster_name":"kind-kind","node_name":"kind-worker","system":{"name":"cilium-agent","version":"1.19.0-dev"},"started_at":"2025-10-15T15:00:35.357047077Z","total_conditions":3,"failing_conditions":[{"condition_id":"hive_degraded_modules","severity":"SEVERITY_DEBUG","message":"Degraded modules: dummy.dummy"}]}},"time":"2025-10-15T15:05:54.891177812Z","node_name":"kind-worker"}
```

Do note that the default evaluation period is 5 minutes and thus it takes 5 minutes for
the `status.log` to be created. This can be configured to be lower with
e.g. `cilium config set diagnostics-interval 5s`.

## Timescape

On the Timescape side we have:
- `system_status_updates` and `system_status_metadata` ClickHouse tables
- Ingestion of updates and metadata that insert into these tables
- "SystemStatus" gRPC service for querying these tables:
  * GetSummary returns list of failing conditions along with node counts
  * GetTimeline returns counts of failing conditions or nodes over time
  * GetDetails returns the nodes and associated messages for a single condition
- The status UI showing a timeline, table of failures and a modal details
  for a selected failing condition.
