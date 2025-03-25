#!/usr/bin/env python3
import argparse
import asyncio
import time
from urllib.parse import urlparse
import aiohttp
import statistics
from concurrent.futures import ProcessPoolExecutor
import os


async def fetch_file(session, url, request_id):
    """Fetch a file from the server and measure time and bytes."""
    start_time = time.time()
    try:
        async with session.get(url) as response:
            content = await response.read()
            end_time = time.time()
            return {
                "request_id": request_id,
                "status": response.status,
                "size": len(content),
                "time": end_time - start_time,
            }
    except Exception as e:
        end_time = time.time()
        return {
            "request_id": request_id,
            "status": "error",
            "error": str(e),
            "time": end_time - start_time,
        }


async def run_batch(url, num_requests, batch_id, timeout=30):
    """Run a batch of requests in parallel."""
    conn = aiohttp.TCPConnector(limit=0)  # Unlimited connections
    timeout_obj = aiohttp.ClientTimeout(total=timeout)

    async with aiohttp.ClientSession(connector=conn, timeout=timeout_obj) as session:
        tasks = []
        for i in range(num_requests):
            request_id = f"{batch_id}_{i}"
            task = fetch_file(session, url, request_id)
            tasks.append(task)

        return await asyncio.gather(*tasks)


def run_worker(url, num_requests, worker_id, timeout):
    """Process pool worker to run a batch of requests."""
    # Create a new event loop for this process
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Run the batch and return results
    results = loop.run_until_complete(run_batch(url, num_requests, worker_id, timeout))
    return results


async def main():
    parser = argparse.ArgumentParser(description="HTTP File Read Benchmark Tool")
    parser.add_argument("url", help="URL to the file to download")
    parser.add_argument(
        "-n",
        "--num-requests",
        type=int,
        default=100,
        help="Total number of requests to make (default: 100)",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=10,
        help="Number of concurrent requests (default: 10)",
    )
    parser.add_argument(
        "-p",
        "--processes",
        type=int,
        default=1,
        help="Number of processes to use (default: 1)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print detailed information about each request",
    )

    args = parser.parse_args()

    if args.concurrency > args.num_requests:
        args.concurrency = args.num_requests

    print(f"Starting benchmark for {args.url}")
    print(
        f"Total requests: {args.num_requests}, Concurrency: {args.concurrency}, Processes: {args.processes}"
    )

    url_parts = urlparse(args.url)
    if not url_parts.scheme or not url_parts.netloc:
        print("Invalid URL. Please include scheme (http:// or https://)")
        return

    start_time = time.time()

    # Calculate requests per process
    requests_per_process = args.num_requests // args.processes
    remainder = args.num_requests % args.processes

    # Distribute requests to processes
    process_requests = []
    for i in range(args.processes):
        proc_requests = requests_per_process + (1 if i < remainder else 0)
        if proc_requests > 0:
            process_requests.append((args.url, proc_requests, i, args.timeout))

    all_results = []

    # Use process pool to handle requests
    with ProcessPoolExecutor(max_workers=args.processes) as executor:
        loop = asyncio.get_event_loop()
        futures = [
            loop.run_in_executor(executor, run_worker, *params)
            for params in process_requests
        ]

        for future in await asyncio.gather(*futures):
            all_results.extend(future)

    end_time = time.time()
    total_time = end_time - start_time

    # Analyze results
    successful_requests = [r for r in all_results if r["status"] == 200]
    failed_requests = [r for r in all_results if r["status"] != 200]

    if successful_requests:
        total_bytes = sum(r["size"] for r in successful_requests)
        request_times = [r["time"] for r in successful_requests]

        # Calculate statistics
        avg_time = statistics.mean(request_times)
        median_time = statistics.median(request_times)
        min_time = min(request_times)
        max_time = max(request_times)
        if len(request_times) > 1:
            stdev_time = statistics.stdev(request_times)
        else:
            stdev_time = 0

        throughput = len(successful_requests) / total_time
        mb_per_sec = (total_bytes / 1024 / 1024) / total_time

        # Print results
        print("\n=== Benchmark Results ===")
        print(f"Total time: {total_time:.2f} seconds")
        print(f"Successful requests: {len(successful_requests)}")
        print(f"Failed requests: {len(failed_requests)}")
        print(f"Requests per second: {throughput:.2f}")
        print(f"Total data transferred: {total_bytes / 1024 / 1024:.2f} MB")
        print(f"Throughput: {mb_per_sec:.2f} MB/s")
        print("\nLatency statistics:")
        print(f"  Average: {avg_time * 1000:.2f} ms")
        print(f"  Median: {median_time * 1000:.2f} ms")
        print(f"  Min: {min_time * 1000:.2f} ms")
        print(f"  Max: {max_time * 1000:.2f} ms")
        print(f"  StdDev: {stdev_time * 1000:.2f} ms")

        if args.verbose and failed_requests:
            print("\nFailed Requests:")
            for i, req in enumerate(failed_requests, 1):
                print(
                    f"  {i}. Request {req['request_id']}: {req.get('status')} - {req.get('error', 'Unknown error')}"
                )
    else:
        print("\nNo successful requests!")
        print(f"Failed requests: {len(failed_requests)}")

        if failed_requests:
            print("\nFailed Requests:")
            for i, req in enumerate(failed_requests[:10], 1):
                print(
                    f"  {i}. Request {req['request_id']}: {req.get('status')} - {req.get('error', 'Unknown error')}"
                )
            if len(failed_requests) > 10:
                print(f"  ... and {len(failed_requests) - 10} more errors")


if __name__ == "__main__":
    asyncio.run(main())
