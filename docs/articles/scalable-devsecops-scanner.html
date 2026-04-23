# Designing a Scalable Vulnerability Scanning Pipeline: An Asynchronous Architecture Case Study

We needed to scan thousands of repositories — Python and Node.js — for known vulnerabilities, run the scans in isolated environments, and deliver PDF and Excel reports to security teams. The naive approach of performing the scan inside the request-response cycle collapsed the moment we hit a 10‑minute scan time on a mid‑size monorepo. What follows is a dissection of the architecture we settled on, the trade‑offs we made, and the scars we earned along the way.

## The Sync Trap: Why Not `async def`

FastAPI is built on ASGI and can handle thousands of concurrent connections via cooperative multitasking. That works beautifully for I/O-bound workloads — calling an external API, waiting for a database query. But a vulnerability scan is **CPU‑ and I/O‑intensive** in an unbounded way:

- Cloning or updating a repo can saturate disk I/O for minutes.
- Running `pip-audit` or `npm audit` inside a Docker container consumes CPU and memory unpredictably.
- Generating richly formatted PDFs from a large dependency tree is itself a heavy task.

If we embed this work inside an endpoint, even one declared `async`, we block the event loop and choke the API’s capacity. Quick back‑of‑the‑envelope: a single scan taking 8 minutes holds the connection open, exhausts gunicorn/uvicorn worker slots, and pushes p99 latency into the thousands of seconds. HTTP timeouts (load balancers, reverse proxies, clients) will fire long before the scan finishes, and the server burns resources without any benefit.

**Synchronous vs. asynchronous processing in the API context** isn’t about `async def` vs `def` — it’s about **decoupling the API’s response lifecycle from the execution of the scan**. The API’s job is to accept work and return a receipt. The real work happens elsewhere.

Thus: background workers.

## Architecture at a Glance
[Client]
│
▼
[FastAPI] ──enqueue──▶ [Redis (RQ)]
│ │
│ ◄──202 + scan_id ▼
│ [Worker (RQ)]
│ │
│ ├─ docker run <scanner-image>
│ ├─ parse results (JSON)
│ ├─ build PDF / Excel
│ └─ store in S3, update DB
◄───── poll / webhook for status ────────────┘

text

**Stack choices and rationale:**

- **FastAPI**: We already had Python expertise; it gives us async endpoints for lightweight polling and webhooks without blocking worker threads.
- **Redis + RQ**: We deliberately chose RQ over Celery. RQ requires only Redis, its API is intentionally minimal, and it maps cleanly onto our “function‑centric” scan jobs. The trade‑off is a lack of mature AMQP‑style acknowledgements, built‑in scheduling, or complex routing — but we didn’t need those yet. We compensated for RQ’s shortcomings with a few hundred lines of custom supervisor logic, which we’ll detail later.
- **Docker for isolation**: Every scan runs in its own throwaway container. This guarantees that a malicious `setup.py` cannot touch the worker’s filesystem, and that `npm` and `pip` environments never cross‑contaminate.
- **Report generation**: We started with ReportLab for PDF and OpenPyXL for Excel, both invoked inside the worker after the scanner finishes.

## Deep Dive: Enqueue, Dequeue, and the State Machine

### API endpoint (simplified)

```python
from rq import Queue
from rq.retry import Retry
from redis import Redis

redis_conn = Redis.from_url(settings.REDIS_URL)
scan_queue = Queue("scans", connection=redis_conn)

@router.post("/scans", status_code=202)
async def request_scan(payload: ScanRequest):
    scan_id = str(uuid4())
    scan_rec = await db.insert(
        id=scan_id, repo=payload.repo_url, status="queued"
    )
    job = scan_queue.enqueue(
        "worker.scan_repo",
        scan_id,
        payload.repo_url,
        payload.flags,
        job_id=scan_id,
        retry=Retry(max=3, interval=[10, 60, 300]),
        job_timeout="35m",
    )
    return {"scan_id": scan_id, "status_url": f"/scans/{scan_id}"}
A few design decisions embedded here:

Job id = scan_id: makes linking a failed job in the RQ dashboard to the database row trivial.

Default timeout is huge (35 min) because we never want RQ’s SIGALRM to kill the worker process. We handle timeouts ourselves inside the job using a subprocess deadline.

Retry policy: Exponential-ish backoff with a cap. RQ 1.12+ supports this natively; earlier we hacked it with a custom failure handler.

Worker job skeleton
python
import subprocess, tempfile, json, shutil
from pathlib import Path
from docker import from_env

def scan_repo(scan_id: str, repo_url: str, flags: dict):
    log_ctx = {"scan_id": scan_id, "repo": repo_url}
    update_status(scan_id, "running")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Shallow clone to save time and disk
            _shallow_clone(repo_url, tmpdir, log_ctx)

            # Start container; bind mount the repository read-only
            client = from_env()
            container = client.containers.run(
                image=f"scanner-{flags['lang']}:latest",
                command=["scan", "/repo"],
                volumes={tmpdir: {"bind": "/repo", "mode": "ro"}},
                detach=True,
            )
            # Hard timeout inside the worker: send SIGTERM then SIGKILL
            try:
                container.wait(timeout=1800)  # 30 minutes
            except subprocess.TimeoutExpired:
                container.kill()
                raise ScanTimeoutError(f"scan exceeded 30 min")
                
            logs = container.logs().decode()
            results = parse_scanner_output(logs, flags["lang"])
            
            # Persist raw results
            store_raw_results(scan_id, results)
            update_status(scan_id, "scan_completed")
            
            # Delegate report generation to another queue
            report_queue.enqueue(
                "worker.generate_reports",
                scan_id, results,
                retry=Retry(max=2, interval=60),
            )
    except Exception as exc:
        update_status(scan_id, "failed", error=str(exc))
        raise  # let RQ retry logic handle it
Note the pipeline split: after scanning we enqueue a separate job for reports. This decouples the heavy report generation from the scanning logic. If the PDF generation consumes too much memory and dies, we can retry just that step without re‑scanning the entire repository. It also lets us scale scanning and reporting workers independently.

Performance Bottlenecks and Mitigations
1. Docker Image Pull Latency
Every new worker node pulls a 800MB scanner image on its first scan. We pre‑pull images at node startup using an init container in Kubernetes, and we use a local registry mirror. In the worker we don’t remove images after scan; the Docker daemon’s LRU cache keeps them warm.

2. Queue Length Explosion
A sudden submission of 500 repos can swamp the scan queue, causing job latency to spike to hours.
Mitigation:

Rate limiting at the API gateway (token bucket per API key).

Two priority queues: scans-high (interactive user requests) and scans-bulk (CI‑triggered). RQ workers can listen to multiple queues with priority order.

Hard cap on queue depth: if LLEN exceeds a threshold, API returns 503 with Retry-After.

3. Worker Saturation and Noisy Neighbors
A single worker process runs one job at a time. But Docker containers on the same host compete for CPU/IO. We cap concurrent Docker containers per host using a semaphore inside the worker:

python
import threading
docker_sem = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)

def scan_repo_wrapper(*args):
    with docker_sem:
        scan_repo(*args)
In Kubernetes, we couple this with pod anti‑affinity and node resource reservations. Horizontal Pod Autoscaler scales worker pods based on rq:queue:scans length (exported to Prometheus).

4. Monorepos and Clone Overhead
A shallow clone (--depth 1) saves time, but for monorepos with large history the .git directory still can be hundreds of MB. We considered partial clone (--filter=blob:none) but wheel of the scanner tools expected all files locally. As a stopgap, we mount a shared NFS cache of already‑cloned repos, updated asynchronously by a sidecar — but this introduced coupling we’re not proud of. The current fix is to throw faster network and ephemeral NVMe at the problem, combined with a per‑repo TTL‑based cache on the worker nodes.

5. Report Generation Memory Pressure
A dependency tree with 2000+ modules can produce a PDF exceeding 100 MB that takes minutes to render. We moved PDF generation to a separate queue of workers with higher memory limits, and we use ReportLab’s incremental writing to disk to avoid holding the full PDF in RAM.

Failure Scenarios and Recovery Design
Scenario: Worker Hard‑Crash Mid‑Scan
An OOM kill or host failure leaves the RQ job in the started registry indefinitely. RQ’s default behaviour is to ignore it. We built a stuck‑job reaper that runs every 2 minutes inside the API (or a separate cron) and does:

python
from rq.registry import StartedJobRegistry
registry = StartedJobRegistry("scans", connection=redis_conn)
threshold = datetime.utcnow() - timedelta(minutes=40)
for job_id in registry.get_job_ids():
    job = Job.fetch(job_id, connection=redis_conn)
    if job.started_at < threshold:
        registry.remove(job, delete_job=False)
        job.meta["reaped"] = True
        scan_queue.enqueue_job(job)  # re-queue it
We set the reaper interval larger than the scan timeout to avoid false positives. Combined with the retry policy, a transient host failure results in at most a 40‑minute gap before the job restarts.

Scenario: Scan Timeout
We use container.wait(timeout=...) as shown. This kills the container gracefully and allows the worker to mark the job as failed with ScanTimeoutError. We deliberately do not rely on RQ’s job_timeout for this because it sends SIGKILL to the entire worker process, aborting any other jobs and leaving no chance for cleanup.

Scenario: Redis Out‑of‑Memory
RQ stores job data, results, and all registries in Redis. A flurry of large payloads can blow memory. We enforce:

Max job payload size rejection at the API layer (compress repo metadata).

volatile-lru eviction policy on Redis, with a separate instance for job data so that cache evictions don’t affect scanning state.

Results are never stored in Redis; we only keep a lightweight reference (S3 path) in the database.

Scenario: Database Unavailability
The worker cannot update status. We wrap status updates with an exponential backoff (up to 5 retries) and, if all fail, abort the job with a clear “DB write failed” error. The reaper will later re‑try the whole job.

Observability: Metrics, Logs, and Tracing
Every component emits structured JSON logs with at least scan_id, job_id, and stage. We also instrument custom Prometheus metrics:

python
from prometheus_client import Histogram, Counter, Gauge

queue_latency = Histogram(
    "scan_queue_latency_seconds",
    "Time from enqueue to start",
    buckets=[0.5, 1, 5, 10, 30, 60, 300],
)
job_duration = Histogram(
    "scan_job_duration_seconds",
    "Total wall time for scan+report",
)
queue_length = Gauge("scan_queue_length", "RQ jobs in scans queue")
job_outcomes = Counter("scan_job_total", "Result", ["outcome"])
On job start, we record job.enqueued_at from Job metadata and compute latency. On success/failure, we increment the counter. A separate exporter uses rq.Queue introspection to set the gauge.

Example baseline metrics for 200 concurrent scans/day:

API p95 latency (POST /scans): 12 ms

Queue latency p95: 3.2 seconds (driven by worker pool size)

Scan processing time p50: 4 min, p95: 18 min

Job failure rate: 0.6% (almost entirely timeout on abandoned monorepos)

Alerts trigger when scan_queue_length > 100 for 5 minutes, or when the failure rate exceeds 2% over a rolling window.

What We Would Do Differently
Use a task system with native priority and dead‑letter‑queues (Celery, or an SQS‑based pipeline) instead of building our own reaper. RQ worked until we hit multi‑region deployments where Redis latency became a bottleneck.

Stream results back rather than storing giant JSON blobs. We now push individual vulnerability findings into an event stream so the report generator can start before the scan finishes.

Invest in a proper resource scheduler (like Nomad or Kubernetes Jobs) that natively understands container lifecycles and disk quotas, instead of a flat worker pool with semaphores.

Conclusion
An asynchronous architecture with background workers isn’t optional for vulnerability scanning — it’s the only way to keep the API responsive and avoid losing work to timeouts. The core pattern — API enqueues a job, workers provide isolation and retry, and a reaper handles process death — has held up under load. The real effort goes into anticipating failure modes (stuck jobs, timeouts, resource exhaustion) and instrumenting the system so that when things inevitably go wrong, you’re not guessing what happened.

If you’re building a similar system, start with the reaper and a split between scanning and report generation. Those two design choices alone saved us from countless 2 a.m. pages.
