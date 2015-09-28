#/bin/sh
PYTHON2="/usr/lib/python2.7"
PYTHON3="/usr/lib/python3.4"
PYTHON=""
os_name="$(uname -s)"

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

if [ "Linux" == "$os_name" ]; then
	sudo cp gdb_attach /usr/bin/
	sudo cp sct /usr/bin/
fi
