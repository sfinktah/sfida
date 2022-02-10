import timeit
import idc
from collections import defaultdict
from mypprint import MyPrettyPrinter

pp = MyPrettyPrinter(indent=4).pprint
pf = MyPrettyPrinter(indent=4).pformat


class PerfTimer(object):
    timer = None
    name = None
    start_times = dict()
    stop_times = dict()
    times = defaultdict(list)

    def __init__(self, name):
        self.timer = timeit.default_timer
        self.name = name

    def __enter__(self):
        self.start_times[self.name] = self.timer()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop_times[self.name] = self.timer()
        self.times[self.name].append(self.stop_times[self.name] - self.start_times[self.name])
        # print("{}: {}ms".format(self.name, float(sum(self.times[self.name])) / len(self.times[self.name])))
        t = len(self.times[self.name])
        if 0:
            if not t % 1000:
                self.avg()
                #  r = ("{} ms - {}: {}ms".format(sum(self.times[self.name]), t, self.name, ))
                #  pp(r)


    def avg(self):
        for name in self.stop_times:
            print("{:8}: {} ms avg".format(name, float(1000.0 * sum(self.times[name])) / len(self.times[name])))
            # print("{}: {}ms total".format(name, sum(self.times[name])))
            # print("")
        count = 0
        time = 0
        #  for name, times in self.times.items():
            #  ++count
            #  time += sum(times)
            #  print("{}: {}ms".format("all", time))


