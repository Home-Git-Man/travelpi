"""Entry point: network controller thread + touch screen (python3 -m travelpi)."""
from __future__ import annotations

import logging
import threading

from .net import Net


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    net = Net()
    import signal, sys
    def stop(*_: object) -> None:          # save the day's data counters on shutdown/restart
        net.save_usage()
        sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
    threading.Thread(target=net.loop, daemon=True, name="net").start()
    try:
        from .web import serve
        serve(net)
    except Exception:
        logging.exception("control page unavailable")
    try:
        from .screen import Framebuffer, Touch, blank_console
        from .ui import App
        blank_console()
        App(net, Framebuffer(), Touch()).run()
    except Exception:
        logging.exception("screen unavailable – running the network controller only")
        threading.Event().wait()


if __name__ == "__main__":
    main()
