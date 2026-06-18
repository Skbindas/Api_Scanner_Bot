"""
Async handler for bridging asyncio operations with Tkinter.

Provides a threading-based solution for running async operations
without blocking the Tkinter main loop. Uses a daemon thread running
its own asyncio event loop, with safe callback scheduling via root.after().

IMPORTANT: This is the CORRECT pattern for async in Tkinter.
Never use asyncio.run() in button callbacks.
"""

import asyncio
import threading
from typing import Any, Callable, Coroutine, Optional
import tkinter as tk


class AsyncHandler:
    """Bridges async coroutines with the Tkinter event loop.

    Runs an asyncio event loop in a separate daemon thread and provides
    a submit() method for scheduling coroutines. Completion and error
    callbacks are dispatched back to the Tkinter main thread using
    root.after() for thread-safe GUI updates.

    Attributes:
        root: The Tkinter root window for scheduling callbacks.
    """

    def __init__(self, root: tk.Tk) -> None:
        """Initialize the AsyncHandler.

        Creates a daemon thread running its own asyncio event loop.
        Uses a threading.Event to wait efficiently for the loop to
        become available, with a timeout to avoid hanging indefinitely.

        Args:
            root: The Tkinter root widget for scheduling callbacks on
                  the main thread.

        Raises:
            RuntimeError: If the event loop fails to start within 5 seconds.
        """
        self.root = root
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_ready = threading.Event()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

        # Wait for the loop to be created with a timeout
        if not self._loop_ready.wait(timeout=5.0):
            raise RuntimeError(
                "AsyncHandler: background event loop failed to start within 5 seconds"
            )

    def _run_loop(self) -> None:
        """Run the asyncio event loop in the background thread.

        This method runs indefinitely in the daemon thread. It creates
        a new event loop, signals readiness, and runs until the thread
        is terminated.
        """
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop_ready.set()
        self._loop.run_forever()

    def submit(
        self,
        coro: Coroutine[Any, Any, Any],
        on_complete: Optional[Callable[[Any], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Submit an async coroutine for execution.

        Schedules the coroutine on the background event loop. When
        completed, the on_complete or on_error callback is dispatched
        to the Tkinter main thread via root.after().

        Args:
            coro: The async coroutine to execute.
            on_complete: Callback invoked with the result on success.
                         Called on the main (Tkinter) thread.
            on_error: Callback invoked with the exception on failure.
                      Called on the main (Tkinter) thread.
            on_progress: Optional callback for progress updates.
                         Called on the main (Tkinter) thread.
        """
        if self._loop is None:
            if on_error:
                on_error(RuntimeError("Event loop not initialized"))
            return

        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        future.add_done_callback(
            lambda f: self._task_done(f, on_complete, on_error)
        )

    def _task_done(
        self,
        future: asyncio.Future[Any],
        on_complete: Optional[Callable[[Any], None]],
        on_error: Optional[Callable[[Exception], None]],
    ) -> None:
        """Handle task completion by scheduling callback on main thread.

        This method is called from the background thread when a task
        completes. It schedules the appropriate callback on the Tkinter
        main thread using root.after().

        Args:
            future: The completed future from the background loop.
            on_complete: Success callback to schedule on the main thread.
            on_error: Error callback to schedule on the main thread.
        """
        try:
            result = future.result()
            if on_complete:
                self.root.after(0, on_complete, result)
        except Exception as exc:
            if on_error:
                self.root.after(0, on_error, exc)

    def shutdown(self) -> None:
        """Shut down the background event loop.

        Stops the event loop running in the daemon thread. This should
        be called when the application is closing.
        """
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
