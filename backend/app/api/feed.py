import asyncio
import json

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from app.services.event_bus import EventBus

router = APIRouter(prefix="/feed", tags=["Live Feed"])

# How often to send a keep-alive ping if no real event arrives in that window.
PING_INTERVAL_SECONDS = 15


async def _event_generator(request: Request):
    """
    Streams live SOC events to the browser over Server-Sent Events.

    Backed by Redis pub/sub (channel: dashboard_feed) instead of polling
    Postgres. The Coordinator publishes here the instant it saves a new
    alert, so events are pushed in real time rather than surfacing on the
    next poll tick.

    A background task drains the Redis pub/sub subscription into a plain
    asyncio.Queue; the generator below just waits on that queue (with a
    timeout for keep-alive pings). This keeps cancellation simple: closing
    the SSE connection cancels the background task directly instead of
    reaching into a suspended async generator mid-`await`.

    Event types forwarded, in the order a single simulated attack produces
    them:
      connected  - fired once, right after the client subscribes
      detection  - simulated_detections stage
      analysis   - simulated_analysis stage
      response   - simulated_response stage
      new_alert  - final, complete alert (same shape the old polling code
                   sent — this is what the existing frontend hook listens for)
      ping       - keep-alive, sent if nothing else arrives for a while
    """
    queue: asyncio.Queue = asyncio.Queue()

    async def _drain_subscription():
        async for message in EventBus.subscribe(EventBus.CHANNEL_DASHBOARD):
            await queue.put(message)

    drain_task = asyncio.create_task(_drain_subscription())

    yield "event: connected\ndata: {\"status\": \"connected\"}\n\n"

    try:
        while True:
            if await request.is_disconnected():
                break

            try:
                message = await asyncio.wait_for(
                    queue.get(), timeout=PING_INTERVAL_SECONDS
                )
            except asyncio.TimeoutError:
                yield "event: ping\ndata: {\"status\": \"alive\"}\n\n"
                continue

            event_type = message.get("type", "message")
            payload = json.dumps(message.get("data", {}))
            yield f"event: {event_type}\ndata: {payload}\n\n"

    except asyncio.CancelledError:
        pass
    finally:
        drain_task.cancel()
        try:
            await drain_task
        except (asyncio.CancelledError, Exception):
            pass


@router.get("")
async def sse_feed(request: Request):
    """
    Server-Sent Events endpoint for the live alert feed, backed by Redis
    pub/sub.

    Frontend usage (unchanged):
        const es = new EventSource("http://localhost:8000/feed");
        es.addEventListener("new_alert", (e) => {
            const alert = JSON.parse(e.data);
            // update dashboard
        });
    """
    return StreamingResponse(
        _event_generator(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"   # disable nginx buffering if behind proxy
        }
    )
