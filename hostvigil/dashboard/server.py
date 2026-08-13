"""Production WSGI server launcher for the HostVigil dashboard.

Uses gunicorn when available, falls back to Flask's built-in werkzeug server.
"""

import logging

logger = logging.getLogger("hostvigil")

GUNICORN_DEFAULTS = {
    "workers": 2,
    "threads": 4,
    "worker_class": "gthread",
    "timeout": 120,
    "accesslog": "-",
    "errorlog": "-",
    "loglevel": "warning",
}


def run_server(app, host: str = "127.0.0.1", port: int = 5000) -> None:
    """Run the Flask app with gunicorn (production) or werkzeug (fallback).

    Blocks until the server stops. Safe to call from a background thread
    in daemon mode — gunicorn forks its own workers from here.
    """
    try:
        from gunicorn.app.base import BaseApplication

        class HostVigilServer(BaseApplication):
            def __init__(self, application, opts):
                self.application = application
                self.options = opts
                super().__init__()

            def load_config(self):
                for key, value in self.options.items():
                    if key in self.cfg.settings and value is not None:
                        self.cfg.set(key.lower(), value)

            def load(self):
                return self.application

        options = {"bind": f"{host}:{port}", **GUNICORN_DEFAULTS}
        logger.info("Starting dashboard with gunicorn on %s:%s", host, port)
        HostVigilServer(app, options).run()

    except ImportError:
        logger.warning("gunicorn not installed — falling back to werkzeug dev server")
        app.run(host=host, port=port, debug=False, use_reloader=False)
