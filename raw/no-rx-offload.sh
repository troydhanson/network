#!/bin/bash
IF=$1
if [ -z "$IF" ]; then echo "provide interface argument"; exit -1; fi
ethtool -K $IF tso off
ethtool -K $IF ufo off
ethtool -K $IF gso off
ethtool -K $IF gro off
ethtool -K $IF lro off
