#!/usr/bin/env python
#
# $Id: wrap.py,v 1.2 2006/07/12 07:05:32 jtr Exp $
#
import log
import types

class Wrapper:
  attr_dict = {}
  free_ptr = 0
  ptr = del_func = new_func = None
  def __init__(self, ptr=None, new_func=None, del_func=None,
      attr_dict=None):
    if attr_dict:
      self.__dict__['attr_dict'] = attr_dict
    else:
      self.__dict__['attr_dict'] = {}
    self.free_ptr = 0
    if ptr is None and new_func is not None:
      ptr = new_func()
      if ptr is None:
        raise MemoryError, "Unable to allocate memory."
      self.free_ptr = 1
    self.new_func = new_func
    self.del_func = del_func
    self.ptr = ptr


  def __del__(self):
    if self.free_ptr and self.del_func is not None:
      self.del_func(self.ptr)


  def __str__(self):
    return '<%s at 0x%x>' % (self.__class__, id(self))


  def __getattr__(self, name):
    if self.__dict__['attr_dict'].has_key(name):
      attr_data = self.attr_dict[name]
      value = attr_data[0](self.ptr)
      if attr_data[2] is not None:
        value = attr_data[2](value)
      self.__dict__[name] = value
      return value
    raise AttributeError, ("%s instance has no attribute '%s'" %
        (self.__class__, name))


  def __setattr__(self, name, value):
    if self.__dict__.has_key(name):
      self.__dict__[name] = value
    if self.__dict__['attr_dict'].has_key(name):
      attr_data = self.attr_dict[name]
      if type(value) == types.InstanceType:
        attr_data[1](self.ptr, value.ptr)
      else:
        attr_data[1](self.ptr, value)
    self.__dict__[name] = value
