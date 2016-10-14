#!/usr/bin/python

import re
import sys
import os
import fnmatch
import math

## bugs to vladimir dot kulyukin at usu dot edu

## --------- GENERATING FILE NAMES

def generate_file_names(fnpat, rootdir):
  pass

def unit_test_01(fnpat, rootdir):
  for fn in generate_file_names(fnpat, rootdir):
    print fn

## ----------- GENERATING INPUT STREAMS & LINES
      
def generate_input_streams(gen_filenames):
  pass

def generate_lines(gen_instreams):
  pass

def unit_test_02(fnpat, rootdir):
  fns = generate_file_names(fnpat, rootdir)
  instreams = generate_input_streams(fns)
  lns = generate_lines(instreams)
  for ln in lns:
    print ln,

## ----------- GENERATING TOOPS OF IPS and TRANSFERRED BYTES

def generate_ip_trbts_toops(pat, gen_lines, ip_group_num=1, trbytes_group_num=9):
 pass

ip_trbts = {}
def count_ip_trbts(gen_ip_trbts_toops):
  global ip_trbts
  pass

def unit_test_03(fnpat, rootdir):
  logpat = r'^([\d\.\w-]+)\s+(- -)\s+\[(\d{2}\/\w{3}\/\d{4}):(\d{2}:\d{2}:\d{2}).+\]\s+\"(.+)\s+(.+)\s+(.+)\"\s+(\d+)\s+(\d+)$'
  fns = generate_file_names(fnpat, rootdir)
  instreams = generate_input_streams(fns)
  lns = generate_lines(instreams)
  toops = generate_ip_trbts_toops(logpat, lns, ip_group_num=1, trbytes_group_num=9)
  count_ip_trbts(toops)
  for ip, trbts in ip_trbts.items():
    print ip, '-->', trbts

## ----------- COMPUTING LOG STATS

## call compute_log_stats or pipe_log_stats before calling generate_log_stats.
## pipe_log_stats does the same as compute_log_stats but with fewer lines of code.
def compute_log_stats(fnpat, rootdir):
  logpat = r'^([\d\.\w-]+)\s+(- -)\s+\[(\d{2}\/\w{3}\/\d{4}):(\d{2}:\d{2}:\d{2}).+\]\s+\"(.+)\s+(.+)\s+(.+)\"\s+(\d+)\s+(\d+)$'
  glogs = generate_file_names(fnpat, rootdir)
  gstreams = generate_input_streams(glogs)
  glines = generate_lines(gstreams)
  gip_trbts_toops = generate_ip_trbts_toops(logpat, glines, ip_group_num=1, trbytes_group_num=9)
  count_ip_trbts(gip_trbts_toops)

def pipe_log_stats(fnpat, rootdir):
  logpat = r'^([\d\.\w-]+)\s+(- -)\s+\[(\d{2}\/\w{3}\/\d{4}):(\d{2}:\d{2}:\d{2}).+\]\s+\"(.+)\s+(.+)\s+(.+)\"\s+(\d+)\s+(\d+)$'
  glines = generate_lines(generate_input_streams(generate_file_names(fnpat, rootdir)))
  count_ip_trbts(generate_ip_trbts_toops(logpat, glines, ip_group_num=1, trbytes_group_num=9))
  
def std(seq):
  pass

def top_n(gen_log_stats, n):
  for i in xrange(n+1):
    print gen_log_stats.next()

def generate_log_stats(ip_trbts):
  pass

def unit_test_04(fnpat, rootdir, n):
  global ip_trbts
  compute_log_stats(fnpat, rootdir)
  top_n(generate_log_stats(ip_trbts), n)

## comment and uncomment unit tests as appropriate
if __name__ == '__main__':
  #unit_test_01(sys.argv[1], sys.argv[2])
  #unit_test_02(sys.argv[1], sys.argv[2])
  #unit_test_03(sys.argv[1], sys.argv[2])
  #unit_test_04(sys.argv[1], sys.argv[2], int(sys.argv[3]))
  #compute_log_stats(sys.argv[1], sys.argv[2])
  #pipe_log_stats(sys.argv[1], sys.argv[2])
  #top_n(gen_log_stats(ip_trbts), int(sys.argv[3]))
  pass













