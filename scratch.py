import sys
import os
import time

print('Starting doctor test...')
sys.stdout.flush()

try:
    import redis
    print('Imported redis')
    sys.stdout.flush()
    start = time.time()
    client = redis.from_url('redis://127.0.0.1:6379', socket_connect_timeout=3)
    print('Created client in', time.time() - start)
    sys.stdout.flush()
    start = time.time()
    try:
        client.ping()
        print('Ping successful in', time.time() - start)
    except Exception as e:
        print('Ping failed in', time.time() - start, 'with', e)
    sys.stdout.flush()
    client.close()
except Exception as e:
    print('Error:', e)
