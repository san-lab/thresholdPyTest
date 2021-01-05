
# Threshold signature demo with EC Bilinear Pairing

## Install

```
sudo apt-get install python-dev
sudo apt-get install libssl-dev
sudo apt-get install libffi-dev

pip3 install petlib
python3 -c "import petlib; petlib.run_tests()"

pip install bls-lib
```

## Execute

```
python3 simpleDemo.py
``` 

## Open questions

It seems that order of signatures is important, maybe because of the implementation.

Key generation can be distributed?

# References

https://github.com/asonnino/bls
