#!/usr/bin/python

import re
import sys
import os
import fnmatch
import math

## bugs to vladimir dot kulyukin at usu dot edu

## --------- GENERATING FILE NAMES

def generate_file_names(fnpat, rootdir):
  for path, dirlist, filelist in os.walk(rootdir):
    for file_name in fnmatch.filter(filelist, fnpat):
        yield os.path.join(path, file_name)

def unit_test_01(fnpat, rootdir):
  for fn in generate_file_names(fnpat, rootdir):
    print fn

## ----------- GENERATING INPUT STREAMS & LINES
      
def generate_input_streams(gen_filenames):
  for filename in gen_filenames:
      if filename.endswith('.txt'):
          yield open(filename)

def generate_lines(gen_instreams):
  for stream in gen_instreams:
      for line in stream:
          yield line

def unit_test_02(fnpat, rootdir):
  fns = generate_file_names(fnpat, rootdir)
  instreams = generate_input_streams(fns)
  lns = generate_lines(instreams)
  for ln in lns:
    print ln,

## ----------- GENERATING TOOPS OF IPS and TRANSFERRED BYTES

def generate_ip_trbts_toops(pat, gen_lines, ip_group_num=1, trbytes_group_num=9):
 for line in gen_lines:
     match = re.match(pat, line)
     if match:
         yield (match.group(ip_group_num), match.group(trbytes_group_num))

ip_trbts = {}
def count_ip_trbts(gen_ip_trbts_toops):
  global ip_trbts
  for toop in gen_ip_trbts_toops:
      ip = toop[0]
      bytes = int(toop[1])
      if ip in ip_trbts:
          ip_trbts[ip].append(bytes)
      else:
          ip_trbts[ip] = [bytes]

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
  mean = sum(seq)/len(seq)
  total_deviation = 0
  for x in seq:
    total_deviation += (x-mean)**2
  return math.sqrt(total_deviation/float(len(seq)))

def top_n(gen_log_stats, n):
  for i in xrange(n+1):
    print gen_log_stats.next()

def generate_log_stats(ip_trbts):
  toop_list = []
  for ip, byte_list in ip_trbts.iteritems():
      sumBytes = sum(byte_list)
      num_transfers = len(byte_list)
      std_dev = std(byte_list)
      toop_list.append((ip, sumBytes, num_transfers, std_dev))
  for t in sorted(toop_list, key=lambda k: k[1], reverse=True):
      yield t


def unit_test_04(fnpat, rootdir, n):
  global ip_trbts
  compute_log_stats(fnpat, rootdir)
  top_n(generate_log_stats(ip_trbts), n)

## comment and uncomment unit tests as appropriate
if __name__ == '__main__':
  # unit_test_01(sys.argv[1], sys.argv[2])
  # unit_test_02(sys.argv[1], sys.argv[2])
  # unit_test_03(sys.argv[1], sys.argv[2])
  # unit_test_04(sys.argv[1], sys.argv[2], int(sys.argv[3]))
  #compute_log_stats(sys.argv[1], sys.argv[2])
  #pipe_log_stats(sys.argv[1], sys.argv[2])
  #top_n(gen_log_stats(ip_trbts), int(sys.argv[3]))
  pass
