#!/bin/sh
rm -rf dist/
rm -rf raw_packet.egg-info/
python3 setup.py sdist
pip3 wheel --no-index --no-deps --wheel-dir dist dist/*.tar.gz
python3 -m twine upload --repository testpypi dist/*