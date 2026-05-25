#!/usr/bin/env python3
"""Drain all versioned objects from an S3 bucket in parallel batches.

Usage: BUCKET=<name> python3 drain-s3-bucket.py
"""
import subprocess, json, os, sys, tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

bucket = os.environ.get('BUCKET')
if not bucket:
    print("ERROR: BUCKET environment variable not set", file=sys.stderr)
    sys.exit(1)


def list_all(bucket):
    objs = []
    cmd = ['aws', 's3api', 'list-object-versions', '--bucket', bucket,
           '--no-paginate', '--output', 'json']
    r = subprocess.run(cmd, capture_output=True, text=True)
    data = json.loads(r.stdout or '{}')
    for v in data.get('Versions', []):
        objs.append({'Key': v['Key'], 'VersionId': v['VersionId']})
    for m in data.get('DeleteMarkers', []):
        objs.append({'Key': m['Key'], 'VersionId': m['VersionId']})
    return objs


def delete_batch(bucket, batch, idx, total):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({'Objects': batch}, f)
        tmp = f.name
    try:
        r = subprocess.run(
            ['aws', 's3api', 'delete-objects', '--bucket', bucket,
             '--delete', f'file://{tmp}', '--bypass-governance-retention'],
            capture_output=True, text=True)
        if r.returncode != 0:
            subprocess.run(
                ['aws', 's3api', 'delete-objects', '--bucket', bucket,
                 '--delete', f'file://{tmp}'],
                capture_output=True, text=True)
    finally:
        os.unlink(tmp)
    print(f"  Batch {idx}/{total} complete ({len(batch)} objects)", flush=True)


objs = list_all(bucket)
print(f"Found {len(objs)} object versions to delete")
if not objs:
    print("  Bucket is empty.")
    sys.exit(0)

batches = [objs[i:i+1000] for i in range(0, len(objs), 1000)]
print(f"Deleting {len(batches)} batch(es) in parallel (10 workers)...")

with ThreadPoolExecutor(max_workers=10) as ex:
    futs = {ex.submit(delete_batch, bucket, b, i+1, len(batches)): i
            for i, b in enumerate(batches)}
    for f in as_completed(futs):
        f.result()

print("All batches complete.")
