"""Run with python -m sylanne3.demo. No external messages are sent."""
import asyncio
import json
from pathlib import Path
import tempfile

from .contracts import Event, Scope
from .delivery import RecordingTransport
from .engine import Engine
from .native import NativeKernel
from .scheduler import BoundedScheduler
from .store import Store


async def main():
    with tempfile.TemporaryDirectory(prefix='sylanne3-demo-') as folder:
        store = Store(Path(folder) / 'demo.sqlite')
        scheduler = BoundedScheduler()
        sink = RecordingTransport()
        engine = Engine(store, scheduler, NativeKernel(), sink)
        scope = Scope('local-demo', 'fixture-persona', 'session')
        observation = Event(scope, 'observation', 1., 'interpretation', {
            'interpretation_id': 'attribution', 'subject': {'bot': scope.bot, 'persona': scope.persona, 'session': scope.session},
            'proposition': 'Typed fixture: positive attribution to this scoped subject',
            'drive': [6., 0.], 'start_at': 0.})
        try:
            for event in (observation, observation, Event(scope, 'correction', 3., 'correction', {'target_interpretation_id': 'attribution'})):
                result = await engine.handle(event)
                print(json.dumps({'event': event.event_id, 'status': result.status,
                    'reaction': result.reaction, 'expression': result.action.expression if result.action else None,
                    'delivery': result.delivery_status, 'sink': 'local RecordingTransport only'}))
            print(json.dumps({'local_records': len(sink.sent), 'real_messages_sent': 0}))
        finally:
            await scheduler.close()
            await asyncio.to_thread(store.close)


if __name__ == '__main__':
    asyncio.run(main())
