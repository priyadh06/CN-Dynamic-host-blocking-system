import argparse
import socket
import time


def stamp():
    return time.strftime("%H:%M:%S")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", default="10.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--rate", type=float, default=1.0, help="connections per second")
    p.add_argument("--duration", type=float, default=20.0, help="seconds to run")
    p.add_argument("--label", default="normal")
    a = p.parse_args()

    interval = 1.0 / a.rate
    start = time.time()
    nxt = start
    ok = fail = 0
    last_report = start
    print(f"[{stamp()}] {a.label}: rate={a.rate}/s duration={a.duration}s "
          f"target={a.server}:{a.port}", flush=True)

    while time.time() - start < a.duration:
        try:
            s = socket.create_connection((a.server, a.port), timeout=1.0)
            s.settimeout(1.0)
            s.recv(64)
            s.close()
            ok += 1
        except OSError:
            fail += 1
        now = time.time()
        if now - last_report >= 5:
            print(f"[{stamp()}] {a.label}: ok={ok} fail={fail}", flush=True)
            last_report = now
        nxt += interval
        delay = nxt - time.time()
        if delay > 0:
            time.sleep(delay)
        else:
            nxt = time.time()

    elapsed = time.time() - start
    print(f"[{stamp()}] {a.label} DONE: attempts={ok + fail} ok={ok} fail={fail} "
          f"elapsed={elapsed:.1f}s avg_rate={(ok + fail) / elapsed:.2f}/s", flush=True)


if __name__ == "__main__":
    main()
