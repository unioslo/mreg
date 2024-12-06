#!/bin/bash

# This script is intented to be used with "git bisect run".
# For further information, see: man git bisect

# find out where I am
cd $(dirname $0)
DIR=$(pwd)

# clone mreg-cli
if [[ ! -d /tmp/mreg-cli ]]; then
	cd /tmp
	git clone https://github.com/unioslo/mreg-cli.git
fi

# checkout the correct version of mreg-cli
if [[ -f $DIR/ci/MREG-CLI_COMMIT ]]; then
	C=$(cat $DIR/ci/MREG-CLI_COMMIT)
	cd /tmp/mreg-cli
	git -c advice.detachedHead=false checkout $C
else
	cd /tmp/mreg-cli
	git checkout master
fi

# build the mreg container image
cd $DIR
docker build -t ghcr.io/unioslo/mreg:latest .

# run the tests. pretend we're on GitHub to prevent interactive review
GITHUB_ACTIONS=123 /tmp/mreg-cli/ci/run_testsuite_and_record_V2.sh
EXITCODE=$?

# cleanup
docker rmi ghcr.io/unioslo/mreg:latest
exit $EXITCODE
