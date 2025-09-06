# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
from collections import OrderedDict

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

class IncrementaObject(object):
    def set_normal_attrs(self, value):
        if isinstance(value, IncrementalList):
            normal_value = value.copy()
        elif isinstance(value, IncrementalDict):
            normal_value = value.copy()
        else:
            normal_value = value
        return normal_value

    def set_incremental_attrs(self, value, dict_path, _set=False):
        if isinstance(value, list):
            _list = value
            if _set:
                _list = []
            inc_value = IncrementalList(data=_list,
                                    key=self.key,
                                    dict_path=dict_path,
                                    incremental_data=self.incremental_data)
            if _set:
                inc_value.set(value)
        elif isinstance(value, dict):
            _dict = value
            if _set:
                _dict = {}
            inc_value = IncrementalDict(data=_dict,
                                    key=self.key,
                                    dict_path=dict_path,
                                    incremental_data=self.incremental_data)
            if _set:
                inc_value.set(value)
        else:
            inc_value = value
        return inc_value

class IncrementalDict(IncrementaObject):
    """ Handle incremental updates of dict attribute. """
    def __init__(self, data={}, key=None, dict_path=[], incremental_data=[]):
        self.key = key
        #self.data = {}
        self.type = "dict"
        self.data = OrderedDict()
        self.dict_path = dict_path
        self.incremental_data = incremental_data
        for x in data:
            self.__setitem__(x, data[x])

    def move_to_end(self, key, last=True):
        self.data.move_to_end(key, last=last)
        if last == True:
            action = "move_to_end"
        else:
            action = "move_to_begin"
        self.incremental_data.append((time.time(),
                                    self.key,
                                    action,
                                    self.type,
                                    self.dict_path,
                                    key))
    @property
    def modified(self):
        for x in self.incremental_data:
            if self.key not in x:
                continue
            return True
        return False

    def incremental_add(self, key, value):
        if isinstance(value, IncrementalDict):
            value = value.copy()
        if isinstance(value, IncrementalList):
            value = value.copy()
        self.incremental_data.append((time.time(),
                                    self.key,
                                    'add',
                                    self.type,
                                    self.dict_path,
                                    key, value))

    def incremental_del(self, key, value):
        if isinstance(value, IncrementalDict):
            value = value.copy()
        if isinstance(value, IncrementalList):
            value = value.copy()
        self.incremental_data.append((time.time(),
                                    self.key,
                                    'del',
                                    self.type,
                                    self.dict_path,
                                    key, value))

    def __getitem__(self, key):
        key = str(key)
        return self.data[key]

    def copy(self):
        dict_copy = {}
        for x in self.data:
            x_val = self.data[x]
            if isinstance(x_val, IncrementalDict):
                x_val = x_val.copy()
            if isinstance(x_val, IncrementalList):
                x_val = x_val.copy()
            x_normal_value = self.set_normal_attrs(x_val)
            dict_copy[x] = x_normal_value
        return dict_copy

    def __setitem__(self, key, value):
        key = str(key)
        dict_path = self.dict_path.copy()
        dict_path.append(key)
        inc_value = self.set_incremental_attrs(value, dict_path)
        self.data[key] = inc_value
        add_value  = True
        if isinstance(value, list):
            add_value = False
        if isinstance(value, dict):
            add_value = False
        if not add_value:
            return
        self.incremental_add(key, value)

    def __delitem__(self, key):
        key = str(key)
        del_val = self.data.pop(key)
        self.incremental_del(key, del_val)

    def __len__(self):
        return len(self.data)

    def __iter__(self):
        return iter(self.data)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        _str = self.data.__str__()
        return _str

    def values(self):
        return self.data.values()

    def items(self):
        return self.data.items()

    def keys(self):
        return self.data.keys()

    def pop(self, key):
        key = str(key)
        del_val = self.data.pop(key)
        self.incremental_del(key, del_val)
        return del_val

    def set(self, _dict):
        #self.data = {}
        self.data = OrderedDict()
        for key in _dict:
            key = str(key)
            val = _dict[key]
            dict_path = self.dict_path.copy()
            dict_path.append(key)
            inc_value = self.set_incremental_attrs(val, dict_path, _set=True)
            self.data[key] = inc_value

class IncrementalList(list, IncrementaObject):
    """ Handle incremental updates of list attribute. """
    def __init__(self, data=[], key=None, dict_path=[], incremental_data=[]):
        self.key = key
        self.type = "list"
        self.dict_path = dict_path
        self.incremental_data = incremental_data
        _list = []
        if data is not None:
            _list = data
        for x in _list:
            self.append(x)
        #return super(IncrementalList, self).__init__(_list)

    @property
    def modified(self):
        for x in self.incremental_data:
            if self.key not in x:
                continue
            return True
        return False

    def incremental_add(self, item, index=-1):
        if isinstance(item, IncrementalDict):
            item = item.copy()
        if isinstance(item, IncrementalList):
            item = item.copy()
        self.incremental_data.append((time.time(),
                                    self.key,
                                    'add',
                                    self.type,
                                    self.dict_path,
                                    item,
                                    index))

    def incremental_del(self, item):
        self.incremental_data.append((time.time(),
                                    self.key,
                                    'del',
                                    self.type,
                                    self.dict_path,
                                    item))

    def __setitem__(self, index, item):
        self.incremental_add(item, index=index)
        return super(IncrementalList, self).__setitem__(index, item)

    def __delitem__(self, index):
        del_item = self[index]
        self.incremental_del(del_item)
        return super(IncrementalList, self).__delitem__(index)

    #def copy(self):
    #    list_copy = super(IncrementalList, self).copy()
    #    for x in list_copy:
    #        if isinstance(x, IncrementalDict):
    #            x = x.copy()
    #        if isinstance(x, IncrementalList):
    #            x = x.copy()
    #        #x_normal_value = self.set_normal_attrs(x)
    #        #dict_copy[x] = x_normal_value
    #    return list_copy

    def append(self, value):
        self.incremental_add(value)
        return super(IncrementalList, self).append(value)

    def insert(self, index, value):
        self.incremental_add(value, index=index)
        return super(IncrementalList, self).insert(index, value)

    def pop(self, index=-1):
        del_item = super(IncrementalList, self).pop(index)
        self.incremental_del(del_item)
        return del_item

    def remove(self, value):
        self.incremental_del(value)
        return super(IncrementalList, self).remove(value)

    def set(self, _list):
        super(IncrementalList, self).__init__(_list)

def incremental_update(update_dict, action, key, dict_path, value_type, value=None, index=-1):
    if len(dict_path) > 1:
        root_key = dict_path[0]
        try:
            current_dict = update_dict[root_key]
        except KeyError:
            update_dict[root_key] = {}
            current_dict = update_dict[root_key]
        _dict_dict = current_dict
        counter = 0
        for x_key in dict_path[1:]:
            counter += 1
            if counter == len(dict_path) - 1:
                if value_type == "dict":
                    try:
                        dict_val = _dict_dict[x_key]
                    except KeyError:
                        _dict_dict[x_key] = {}
                        dict_val = _dict_dict[x_key]
                if value_type == "list":
                    try:
                        dict_val = _dict_dict[x_key]
                    except KeyError:
                        _dict_dict[x_key] = []
                        dict_val = _dict_dict[x_key]
            else:
                if x_key not in _dict_dict:
                    _dict_dict[x_key] = {}
            _dict_dict = _dict_dict[x_key]
        if value_type == "list":
            if action == "add":
                if index == -1:
                    dict_val.append(value)
                else:
                    dict_val.insert(index, value)
            if action == "del":
                try:
                    dict_val.remove(value)
                except  ValueError:
                    pass
        if value_type == "dict":
            if action == "add":
                dict_val[key] = value
            if action == "del":
                try:
                    dict_val.pop(key)
                except KeyError:
                    pass
            if action == "move_to_begin":
                dict_val = OrderedDict(dict_val)
                dict_val.move_to_end(key, last=False)
                dict_val = dict(dict_val)
            if action == "move_to_end":
                dict_val = OrderedDict(dict_val)
                dict_val.move_to_end(key)
                dict_val = dict(dict_val)
        value = current_dict
    else:
        if value_type == "dict":
            root_key = dict_path[0]
            try:
                current_dict = update_dict[root_key]
            except KeyError:
                update_dict[root_key] = {}
                current_dict = update_dict[root_key]
            if action == "add":
                current_dict[key] = value
            if action == "del":
                try:
                    current_dict.pop(key)
                except KeyError:
                    pass
            value = current_dict
        if value_type == "list":
            root_key = dict_path[0]
            try:
                current_list = update_dict[root_key]
            except KeyError:
                update_dict[root_key] = []
                current_list = update_dict[root_key]
            if action == "add":
                if index == -1:
                    current_list.append(value)
                else:
                    current_list.insert(index, value)
            if action == "del":
                try:
                    current_list.remove(value)
                except ValueError:
                    pass
            value = current_list
    return value
