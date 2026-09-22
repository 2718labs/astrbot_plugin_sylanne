import unittest
from sylanne3.contracts import Scope, Event, Write

class ContractTests(unittest.TestCase):
    def test_validation_and_digest(self):
        with self.assertRaises(ValueError): Scope('', 'p', 's')
        scope = Scope('b', 'p', 's')
        a = Event(scope, 'id', 1.0, 'kind', {'a': 1, 'b': [2]})
        self.assertEqual(a.digest, Event(scope, 'id', 1.0, 'kind', {'b': [2], 'a': 1}).digest)
        self.assertNotEqual(a.digest, Event(scope, 'id', 2.0, 'kind', a.payload).digest)
        for value in ({'a': float('nan')}, {'a': object()}, {1: 'bad'}, {'a': (1, 2)}):
            with self.assertRaises((ValueError, TypeError)): Write('x', value)
        with self.assertRaises(ValueError): Event(scope, 'id', float('inf'), 'kind', {})



class ContractBoundaryTests(unittest.TestCase):
    def test_input_containers_detached(self):
        from sylanne3.contracts import Atom
        value = {'nested': [1]}
        atom = Atom('x', 1, value)
        write = Write('x', value)
        event = Event(Scope('b','p','s'), 'id', 0, 'kind', value)
        value['nested'].append(2)
        for record in (atom, write): self.assertEqual(record.value, {'nested': [1]})
        self.assertEqual(event.payload, {'nested': [1]})
    def test_cycle_and_boolean_revision_rejected(self):
        from sylanne3.contracts import AtomVersion
        cycle = {}; cycle['cycle'] = cycle
        with self.assertRaises(ValueError): Write('x', cycle)
        with self.assertRaises(ValueError): AtomVersion('x', True)
if __name__ == '__main__': unittest.main()
