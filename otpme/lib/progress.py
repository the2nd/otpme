# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

class ProgressCounter(object):
    def __init__(self, object_count):
        # Number of objects we assume for our progress calculation.
        self.object_count = 0
        # One percent we add to self.progress on each self.count() call.
        self.one_percent = 1
        # The percentage of the overall progress we are at.
        self.progress = 0
        # At this percentage we set the one percent value to the correct one.
        # This is needed because we initially set self.one_percent to 3/4 of
        # the real value because we want to reserve some space for new objects
        # added by add_counter() while proceeding.
        self.recheck_watermark = 50
        # Set object counter.
        self.update_counter(object_count)
        self.last_update = 0.0

    def count(self):
        """ Update progress. """
        self.progress += self.one_percent
        if self.progress > 100:
            self.progress = 100
        if self.progress >= self.recheck_watermark:
            self.one_percent = self.one_percent / 3 * 4
            self.recheck_watermark = 100
        self.last_update = time.time()

    def update_recheck_watermark(self):
        """ Update re-check watermark based on remaining percentage. """
        remaining = 100 - self.progress
        self.recheck_watermark = self.progress + (remaining / 4)

    def update_counter(self, count):
        """ Update object count. """
        self.object_count = count
        self.one_percent = 100 / count / 4 * 3
        self.update_recheck_watermark()

    def add_counter(self, count):
        """ Increase object count. """
        self.object_count += count
        # We need at least on percent remaining for our calc.
        remaining = 100 - self.progress
        if remaining == 0:
            remaining = 1
        self.one_percent = remaining / (self.object_count) / 4 * 3
        # Update re-check watermark.
        self.update_recheck_watermark()

if __name__ == "__main__":
    pg_counter = ProgressCounter(1000)

    for x in range(1, 3000, 1):
        if x == 799:
            pg_counter.add_counter(1100)
        if x == 2900:
            pg_counter.add_counter(900)
        pg_counter.count()
        print(x, pg_counter.progress)
