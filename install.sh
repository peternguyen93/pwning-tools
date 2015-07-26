#/bin/sh
PYTHON2="/usr/lib/python2.7"
PYTHON3="/usr/lib/python3.4"
PYTHON=""

if [ -d "$PYTHON2" ]; then
	echo "Found Python 2"
	PYTHON="$PYTHON2"
elif [ -d "$PYTHON3" ]; then
	echo "Found Python 3"
	PYTHON="$PYTHON3"
else
	exit 1
fi
sudo cp Shellcode.py Pwn.py $PYTHON
