import time, types, os, re
# import timeit
from collections import defaultdict
from superglobals import *
from underscoretest import _

perf_debug = getglobal('perf_debug', False)

_file = os.path.abspath(__file__)
def refresh_perftimer():
    execfile(_file)

def perf_timed(*args, **kwargs):
    """
    @perf_timed
    def func():
        do_stuff()
    """
    def decorate(func):
        #  for k in kwargs: setattr(func, k, kwargs[k])
        #  setattr(func, '__static_vars__', kwargs)
        # pph(inspect.stack())
        stack = inspect.stack()
        outer_name = stack[1].function
        if outer_name != '<module>':
            prefix = outer_name
        else:
            prefix = ".".join(_.initial(os.path.basename(stack[1].filename).split('.')))
        name = "{}.{}".format(prefix, func.__name__)
        setglobal("stack", inspect.stack())
        print("[perftimer] binding as {}".format(name))
        return PerfTimer.bind(func, name)
    return decorate

class PerfTimer(object):
    #  _start_times = getglobal('_perftimer._start_times', type, dict, _set=True)
    #  _stop_times = getglobal('_perftimer._stop_times', type, dict, _set=True)
    _counts = getglobal('_perftimer._count', defaultdict(list), defaultdict, _set=True)
    _depth = []

    #  @property
    #  def start_times(self):
        #  return type(self)._start_times

    #  @start_times.setter
    #  def start_times(self,val):
        #  type(self)._start_times = val

    #  @property
    #  def stop_times(self):
        #  return type(self)._stop_times

    #  @stop_times.setter
    #  def stop_times(self,val):
        #  type(self)._stop_times = val

    @property
    def counts(self):
        return type(self)._counts

    @counts.setter
    def counts(self,val):
        type(self)._counts = val

    @property
    def depth(self):
        return type(self)._depth

    @depth.setter
    def depth(self,val):
        type(self)._depth = val

    def __init__(self, name):
        # self.timer = timeit.default_timer
        self.timer = time.time_ns
        self.name = name
        self.start_times = []
        self.stop_times = []
        self.parent = self.depth[-1] if self.depth else None

    def start(self):
        self.start_times.append(self.timer())
        return self

    def stop(self):
        self.stop_times.append(self.timer())
        _zipped = zip(self.stop_times, self.start_times)
        self.counts[self.name].append(
            sum([e - s for e, s in _zipped])
        )
        return self

    def pause(self):
        self.stop_times.append(self.timer())
        return self


    def resume(self):
        self.start_times.append(self.timer())
        return self


    def __enter__(self):
        if self.parent:
            self.parent.pause()
        self.depth.append(self)
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()
        if self.parent:
            self.parent.resume()
        assert self.depth.pop() == self



    @classmethod
    def clear(cls):
        cls._counts.clear()
        cls._depth.clear()

    @classmethod
    def avg(cls, match='', count=40):
        results = []
        for name, counts in cls._counts.items():
            if not match or re.match(match, name):
                length = len(counts)
                if length:
                    total = sum(counts) / (10 ** 6)
                    avg = total / length
                    results.append((avg, total, length, "{:60}  {:10,.2f}  {:10,.3f}  {:8}".format(name, total, avg, length)))

        group_results = []

        if results:
            group_results.append("---------------------------------------[BY AVG]-----------------------------------------------")
            for result in _.head(_.reverse(_.sortBy(results, lambda v, *a: v[0])), count >> 1):
                group_results.append(result[-1])
            group_results.append("--------------------------------------[BY TOTAL]----------------------------------------------")
            for result in _.head(_.reverse(_.sortBy(results, lambda v, *a: v[1])), count >> 1):
                group_results.append(result[-1])
            group_results.append("--------------------------------------[BY COUNT]----------------------------------------------")
            for result in _.head(_.reverse(_.sortBy(results, lambda v, *a: v[2])), count >> 1):
                group_results.append(result[-1])

            # print("\n".join(_.uniq(group_results)))
            print("\n".join((group_results)))

            # print("{}: {}ms total".format(name, sum(cls.counts[name])))
            # print("")
        #  for name, counts in cls.counts.items():
            #  time += sum(counts)
            #  print("{}: {}ms".format("all", time))

    @classmethod
    def bind(cls, func, name=None):
        """
        bind a function (or list of functions) to PerfTimer, return
        bound versions
        """
        if isinstance(func, list):
            return [cls.bind(x, name=name) for x in func]
        if func.__name__ == 'bound':
            return func
        def bound(*args, **kwargs):
            with PerfTimer(func.__name__ if name is None else name):
                return func(*args, **kwargs)

        for k, v in getattr(func, '__static_vars__', {}).items():
            setattr(bound, k, v)

        return bound


    @classmethod
    def bindmethods(cls, instance, pick=None, omit=None):
        """
        binds class (or an instance of a class) methods to PerfTimer
        """
        methods = [name for name in dir(instance)
                if not name.startswith('_')
                and isinstance(getattr(instance, name), types.MethodType)
                and getattr(instance, name).__name__ != 'bound'
                ]
        if pick:
            methods = _.pick(methods, *pick)
        if omit:
            methods = _.omit(methods, *omit)

        # except AttributeError:
        # dprint("[call_everything] methods")
        # printi("[bindmethods] methods:{}".format(methods))

        instance_name = getattr(instance, '__name__') if hasattr(instance, '__name__') else getattr(instance, '__class__').__name__
        # dprint("[bindmethods] instance_name")
        if perf_debug: print("[bindmethods] instance_name:{}".format(instance_name))

        for name in methods:
            method = getattr(instance, name)
            if perf_debug: print("[bindmethods] {}.{}".format(instance_name, name))
            setattr(instance, name, cls.bind(method, "{}.{}".format(instance_name, name)))

    @classmethod
    def binditems(cls, instance, funcs, name=''):
        """
        binds items in a dict-like object (e.g. locals()) to PerfTimer
        """
        for k, v in instance.items():
            try:
                if v in funcs:
                    if isinstance(v, types.FunctionType):
                        if v.__name__ != 'bound':
                            # dprint("[binditems] v.__name__")
                            if perf_debug: print("[binditems] {}.{}".format(name, k))
                        
                            instance[k] = cls.bind(v, "{}.{}".format(name, k))
            except AttributeError as e:
                # dprint("[binditems] k, v")
                print("[binditems] AttributeError: k:{}, v:{}".format(k, v))
                raise

    @classmethod
    def bindglobalfunctions(cls, *names, pick=None, omit=None):
        names = _.flatten(names)
        methods = _.filter([getglobal(name, None) for name in names if not name.startswith('_') and isinstance(getglobal(name, None), types.FunctionType)])
        if pick:
            methods = _.pick(methods, *pick)
        if omit:
            methods = _.omit(methods, *omit)

        # except AttributeError:
        # dprint("[call_everything] methods")
        # printi("[bindmethods] methods:{}".format(methods))

        for name in methods:
            setglobal(name, cls.bind(getglobal(name), name))


class perf_timer_test_class(object):
    @perf_timed()
    def perftimer_test():
        for r in range(8 * 8 * 8): pass
        print("done")

    def __init__():
        pass
    
def perftimer_outer_test():
    @perf_timed()
    @static_vars(test=2)
    def perftimer_test_inner():
        for r in range(8 * 8 * 8): pass
        print("done -{}".format(perftimer_test_inner.test))

    perftimer_test_inner()


@perf_timed()
@static_vars(test=2)
def perftimer_test():
    for r in range(8 * 8 * 8): pass
    print("done -{}".format(perftimer_test_inner.test))
