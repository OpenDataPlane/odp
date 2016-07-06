#!/usr/bin/python

# Copyright (c) 2015, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

# Usage: git-transplant.py [orig dir] [overlay dir] [interval]
#
# This script generates a list of commits neeeds to be considered for porting
# to the content of [overlay_dir]. It makes a list of all the non-symlinked
# files in [overlay_dir] which exists in [orig_dir], adds the files in
# [orig_dir] added during our interval, and then prints the list of patches.
# It only searches in the interval set by [interval], see 'man gitrevisions'
# Paths are relative to current directory, which has to be a git repo!

import sys
import os
from git import Repo
import subprocess

def usage() :
	print("Usage: git-transplant.py [orig dir] [overlay dir] "
		"[first commit] [last commit]")
	print("Paths are relative to current directory!\n")
	return

if len(sys.argv) != 4 :
	print("\nIncorrect number of parameters!\n")
	usage()
	sys.exit()

current_dir = os.getcwd()
repo = Repo(current_dir)
if repo.bare :
	print("\nThis script should be called inside a git repo!\n")
	usage()
	sys.exit()

orig_dir = sys.argv[1]
overlay_dir = sys.argv[2]
interval = sys.argv[3]

if not os.path.isdir(os.path.join(current_dir, orig_dir)) :
	print("\nCan't open %s!\n" % orig_dir)
	usage()
	sys.exit()

if not os.path.isdir(os.path.join(current_dir, overlay_dir)) :
	print("\nCan't open %s!\n" % overlay_dir)
	usage()
	sys.exit()

# The git command we'll run in the end. --ancestry-path makes sure we only look
# around on one path in the tree (given an interval)
gitlogcmd = "git log --oneline --ancestry-path --no-merges " + interval

# Build a list of all non-symlinked files in [overlay_dir]
for dirname, dirnames, filenames in os.walk(overlay_dir):
	for filename in filenames:
		fullpath = os.path.join(dirname, filename)
		# Ignore symlinks
		if os.path.islink(fullpath) :
			continue
		# Ignore non-versioned files
		if os.system("git ls-files --error-unmatch " + fullpath +
			     " > /dev/null 2>&1") :
			continue
		# Trim overlay_dir from the beginning
		subpath = dirname[len(overlay_dir):]
		# Check if that file exist in orig_dir
		orig_file = os.path.join(current_dir, orig_dir, subpath, filename)
		if not os.path.isfile(orig_file) :
			continue
		gitlogcmd += " " + orig_file

# Print which files the commits change, and grep the new files added
wholefilechanges = "git log --oneline --ancestry-path --name-status " + \
		   interval + " " + orig_dir + " |grep \"^A\""
output = subprocess.check_output([wholefilechanges], shell=True)
for row in output.split('\n') :
	# Ignore empty lines
	if not row :
		continue
	# Remove 'A' and the tab and add the file to the command
	gitlogcmd += " " + os.path.join(current_dir, row[2:])

# Print the list
os.system(gitlogcmd)

