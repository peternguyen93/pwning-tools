#/bin/bash
PYTHON2="/usr/lib/python2.7"
PYTHON3="/usr/lib/python3.4"
PYTHON=""
os_name="$(uname -s)"

if [ "Linux" = "$os_name" ]; then
	if [ -d "$PYTHON2" ]; then
		echo "Found Python 2"
		PYTHON="$PYTHON2"
	elif [ -d "$PYTHON3" ]; then
		echo "Found Python 3"
		PYTHON="$PYTHON3"
	else
		exit 1
	fi

	sudo cp -r Pwn $PYTHON
	sudo cp sct /usr/bin/
	sudo mkdir -p /usr/local/lib/libstdlib32/
	sudo cp stdbuf32/libstdbuf.so /usr/local/lib/libstdlib32/
	sudo cp stdbuf32/stdbuf32.sh /usr/local/bin/stdbuf32
	
elif [ "Darwin" = "$os_name" ]; then
	sudo cp -r Pwn /Library/Python/2.7/site-packages/
fi