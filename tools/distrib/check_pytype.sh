#! /bin/bash -ex
# Copyright 2019 The gRPC Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

JOBS=$(nproc) || JOBS=4

VIRTUALENV=venv_check_pytype
python3.7 -m virtualenv $VIRTUALENV
source $VIRTUALENV/bin/activate

# TODO(xuanwn): update pytype version
python3 -m pip install pytype==2019.11.27
python3 -m pytype --keep-going -j "$JOBS" --strict-import --config "setup.cfg"
