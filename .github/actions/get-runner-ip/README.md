# Get Runner IP

This composite action fetches the runner public IP address from an ordered list of `sources`, parses the response, validates it looks like an IP address, and returns it as an output.

Every source is queried, in order. The first one that answers provides the IP, and the answers from the remaining ones are used as a second opinion: a source that reports a different address gets a warning in the log, not a failure, because a runner behind a SNAT pool can legitimately egress from more than one address. The action only fails when no source answers at all.

## Inputs

- **`sources`** (optional)

  Newline-separated, ordered list of URLs to fetch the runner public IP from.

  It defaults to three endpoints run by independent global infrastructure operators, so that one of them being down does not stop a job:

  - `https://checkip.amazonaws.com`
  - `https://whatismyip.akamai.com`
  - `https://icanhazip.com`

  A response body is either the bare IP address or JSON. JSON is probed for the keys `ip`, `origin`, `query`, `address`, `data.ip` and `data.address`, so no per-source configuration is needed.

- **`source`** (optional, deprecated)

  A single URL, taking precedence over `sources` when set. Use `sources` instead.

## Outputs

- **`ip`**

  The parsed and validated runner public IP address.

- **`mask`**

  The parsed and validated runner public IP mask.

- **`cidr`**

  The parsed and validated runner public IP in CIDR notation.

## Examples

### Use the default sources

```yaml
- name: Get runner IP
  id: runner-ip
  uses: ./.github/actions/get-runner-ip

- name: Print
  run: |
    echo "Runner IP: ${{ steps.runner-ip.outputs.ip }}"
    echo "Runner Mask: ${{ steps.runner-ip.outputs.mask }}"
    echo "Runner CIDR: ${{ steps.runner-ip.outputs.cidr }}"
```

### Use a different list of sources

```yaml
- name: Get runner IP
  id: runner-ip
  uses: ./.github/actions/get-runner-ip
  with:
    sources: |
      https://checkip.amazonaws.com
      https://httpbin.org/ip
```

## Behavior and error handling

- Each source has its own 15 second timeout.

- The action fails if:

  - `sources` is empty
  - every source fails, whether by connection error, timeout, non-2xx response, unparseable body, or a body carrying no IP-like value. The failure lists what each source said.
