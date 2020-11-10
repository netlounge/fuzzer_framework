#!/bin/bash
export CODACY_PROJECT_TOKEN=da6e3d0e9ed646a1adf7615771f4e13e
bash <(curl -Ls https://coverage.codacy.com/get.sh) report
ls
bash <(curl -Ls https://coverage.codacy.com/get.sh) report -l Python -r coverage.xml