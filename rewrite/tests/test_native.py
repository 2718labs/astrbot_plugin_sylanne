from concurrent.futures import CancelledError
import math
from pathlib import Path
import sys
import threading
import unittest
from sylanne3.native import NativeKernel, AccuracyNotMet


REFERENCE_LIBRARY = Path(__file__).resolve().parents[1] / "native" / "target" / "release" / (
    "sylanne3_kernel.dll" if sys.platform == "win32" else
    "libsylanne3_kernel.dylib" if sys.platform == "darwin" else
    "libsylanne3_kernel.so"
)


def dense_solve(a, b):
    rows = [list(row) + [v] for row, v in zip(a, b)]
    n = len(b)
    for k in range(n):
        p = max(range(k, n), key=lambda i: abs(rows[i][k]))
        rows[k], rows[p] = rows[p], rows[k]
        pivot = rows[k][k]
        rows[k] = [v / pivot for v in rows[k]]
        for i in range(n):
            if i != k:
                scale = rows[i][k]
                rows[i] = [v - scale*w for v,w in zip(rows[i], rows[k])]
    return tuple(row[-1] for row in rows)


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.kernel = NativeKernel(REFERENCE_LIBRARY, developer_reference=True)
        self.kw = dict(mass=[2.,3.], recovery=[1.,2.], edges=[[0.,4.],[4.,0.]], previous=[1.,-2.], drive=[3.,1.], dt=.3)

    def solve(self, kw=None, budget=1):
        job = self.kernel.job(**(self.kw if kw is None else kw))
        while True:
            result = job.step(budget, threading.Event())
            if result.done:
                return result.value

    def test_coupled_dense_global_certificate(self):
        result = self.solve()
        a = [[3.5,-1.2],[-1.2,4.8]]
        b = [2.9,-5.7]
        expected = dense_solve(a,b)
        error = math.dist(result.solution, expected)
        residual = math.sqrt(sum((sum(v*x for v,x in zip(row,result.solution))-rhs)**2 for row,rhs in zip(a,b)))
        self.assertLess(error, 1e-8)
        self.assertAlmostEqual(result.residual_l2,residual,places=13)
        self.assertGreaterEqual(result.error_bound + 1e-14,error)

    def test_budget_partition_and_immutable_inputs(self):
        one = self.solve(budget=1)
        many = self.solve(budget=7)
        self.assertEqual(one,many)
        job = self.kernel.job(**self.kw)
        self.kw['drive'][0] = 1e6
        result = job.step(100,threading.Event()).value
        self.assertEqual(result,one)

    def test_no_drive_energy_decay(self):
        self.kw['drive'] = [0.,0.]
        self.assertLess(self.solve().energy_delta,0)

    def test_invalid_inputs(self):
        for patch in [dict(mass=[0,1]),dict(dt=0),dict(recovery=[1,-1]),dict(edges=[[0,1],[2,0]]),dict(edges=[[1,0],[0,0]]),dict(drive=[math.nan,1]),dict(tolerance=-1),dict(max_total_sweeps=0),dict(previous=[1]),dict(mass=[1]*257)]:
            with self.subTest(patch=patch),self.assertRaises((ValueError,TypeError)):
                self.kernel.job(**(self.kw | patch))

    def test_exhaustion_and_cancel(self):
        job = self.kernel.job(**self.kw,max_total_sweeps=1,tolerance=1e-30)
        with self.assertRaises(AccuracyNotMet):
            job.step(1,threading.Event())
        cancelled = threading.Event()
        cancelled.set()
        with self.assertRaises(CancelledError):
            self.kernel.job(**self.kw).step(1,cancelled)

    def test_extreme_finite_parameters_fail_closed(self):
        self.kw['dt'] = 1e308
        with self.assertRaises((ValueError,ArithmeticError)):
            self.solve()



    def test_multidimensional_dense(self):
        n = 5
        mass = [1+i*.2 for i in range(n)]
        recovery = [.5+i*.1 for i in range(n)]
        edges = [[0. if i == j else .2*(1+(i+j)%3) for j in range(n)] for i in range(n)]
        previous = [(-1.)**i*(i+1) for i in range(n)]
        drive = [.3*i for i in range(n)]
        dt = .7
        a = [[(mass[i]+dt*(recovery[i]+sum(edges[i]))) if i==j else -dt*edges[i][j] for j in range(n)] for i in range(n)]
        b = [mass[i]*previous[i]+dt*drive[i] for i in range(n)]
        result = self.solve(dict(mass=mass,recovery=recovery,edges=edges,previous=previous,drive=drive,dt=dt))
        self.assertLess(math.dist(result.solution,dense_solve(a,b)),1e-8)
    def test_cancellation_after_native_call(self):
        from concurrent.futures import CancelledError
        flag = threading.Event()
        original = self.kernel._refine
        def cancel_after(*args):
            status = original(*args)
            flag.set()
            return status
        self.kernel._refine = cancel_after
        with self.assertRaises(CancelledError):
            self.kernel.job(**self.kw).step(64,flag)

    def test_extreme_coupling_cannot_erase_recovery_certificate(self):
        kw = dict(mass=[1.,1.], recovery=[1.,1.], edges=[[0.,1e20],[1e20,0.]],
                  previous=[1.,1.], drive=[-1.,-1.], dt=1.)
        with self.assertRaises(ArithmeticError):
            self.kernel.job(**kw).step(1,threading.Event())

    def test_unattainable_roundoff_tolerance_rejected(self):
        kw = dict(mass=[1.], recovery=[2.], edges=[[0.]], previous=[1.], drive=[0.], dt=1.,tolerance=1e-30)
        with self.assertRaises(ArithmeticError):
            self.kernel.job(**kw).step(64,threading.Event())

    def test_exact_zero_has_no_artificial_roundoff_floor(self):
        kw = dict(mass=[1.,1.], recovery=[1.,1.], edges=[[0.,1.],[1.,0.]],
                  previous=[0.,0.], drive=[0.,0.], dt=1., tolerance=1e-30)
        result = self.kernel.job(**kw).step(1,threading.Event()).value
        self.assertEqual(result.solution,(0.,0.))
        self.assertEqual(result.error_bound,0.)
        self.assertEqual(result.sweeps,0)

if __name__ == '__main__':
    unittest.main()
