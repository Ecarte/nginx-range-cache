# Nginx Range Cache Module
This nginx module provides fixed boundary range requests to request large files
as well as remapping random range requests to fixed ones providing effective
caching in nginx.

# Requirements
Currently this module requires the `range_filter.patch` be applied to the nginx
core. Hopefully this will be upstreamed to nginx so this step won't be needed
in the future.

# Caching Large Files
Using nginx as a reverse caching proxy is great but when the first client requests a
file it must be downloaded in its entirety from the origin before nginx can start
to send it on to the client. For small files this isn't an issue but for large ones
the time taken to receive the file from origin significant, large enough for the
client to time-out waiting for the initial response.

This module uses range requests to avoid this issue, downloading the file in small
chunks which can start to be sent to the client as soon as each chunk is received.

# Efficiently Caching Random Range Requests
Some clients that use range requests do so on random parts of the file
meaning that caching these parts provides little or no benefit.

This module uses fixed boundary range requests to avoid this problem.

# Configuration

This module provides a new nginx config option `range_cache_size` which configures
the size and boundary of range requests sent to the origin, overriding any existing
range request and splitting non-ranged requests.

For each sub request that this module uses to request from the origin it configures
the nginx variable `$range_cache_range` which can be used as the cache key component
to avoid request conflicts.

A good example of how to use this module can be found in
[Multiplay LANcache](https://github.com/multiplay/lancache).
