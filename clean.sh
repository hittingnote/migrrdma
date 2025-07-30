#!/bin/bash

cd src/mlnx-ofed-kernel-5.4/
rm $(find . -name .gitignore)
totl=`git status | wc -l`
headl=`git status | grep Untracked -n | awk -F '[:]' '{print $1}'`
rm $(git status | tail -n `expr ${totl} - ${headl} - 1`) -r
git restore $(git status | grep modified | grep -v "\\.\\." | awk '{print $2}')
git restore $(git status | grep deleted | grep -v "\\.\\." | awk '{print $2}')

cd ../rdma-core-54mlnx1/
rm $(find . -name .gitignore)
totl=`git status | wc -l`
headl=`git status | grep Untracked -n | awk -F '[:]' '{print $1}'`
rm $(git status | tail -n `expr ${totl} - ${headl} - 1`) -r
git restore $(git status | grep modified | grep -v "\\.\\." | awk '{print $2}')
git restore $(git status | grep deleted | grep -v "\\.\\." | awk '{print $2}')

cd ../criu-3.18/
rm $(find . -name .gitignore)
totl=`git status | wc -l`
headl=`git status | grep Untracked -n | awk -F '[:]' '{print $1}'`
rm $(git status | tail -n `expr ${totl} - ${headl} - 1`) -r
git restore $(git status | grep modified | grep -v "\\.\\." | awk '{print $2}')
git restore $(git status | grep deleted | grep -v "\\.\\." | awk '{print $2}')

cd ../runc/
rm $(find . -name .gitignore)
totl=`git status | wc -l`
headl=`git status | grep Untracked -n | awk -F '[:]' '{print $1}'`
rm $(git status | tail -n `expr ${totl} - ${headl} - 1`) -r
git restore $(git status | grep modified | grep -v "\\.\\." | awk '{print $2}')
git restore $(git status | grep deleted | grep -v "\\.\\." | awk '{print $2}')
