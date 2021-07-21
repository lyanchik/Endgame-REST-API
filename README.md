# ENDGAME Python REST API client - Dark Side

## DESCRIPTION:

API allows work with html requests GET, POST, PUT, PATCH, DELETE and visualize the data of the request and response in few formats. 

## PREREQUISITES:

The following programs and add-ons are required for use:

Installed Python 3:
To install in WINDOWS:
```python
https://www.python.org/downloads/windows/ - the official site where you can download.
```
To install in UNIX systems with Tkinter framework:
```python
sudo apt-get install python3 python3-tk
```
To install in macOS:
```python
https://www.python.org/downloads/mac-osx/ - the official site where you can download.
```
Framework Tkinter installation:
```python
$ pip3 install tkinter
```

YAML extension instalation:
```python
$ pip3 install pyyaml
```
Simplejson module instalation:
```python
$ pip3 install simplejson
```
# Usage:
```python
Program operation through the console:
python3 endgame.py [-g, --gui]

To display a help list.
python3 endgame.py [-h, --help] 

optional arguments:
-h, --help
    Show this help message and exit

-g, --gui
    Activate GUI mode

--history {show,clear}
    Show 10 last requests or clear all

-a AUTH AUTH, --auth AUTH AUTH
    Set username and password

-l {debug,info,warning}, --log {debug,info,warning}
    Set logging level

  -m {GET,POST,PUT,PATCH,DELETE}, --method 
{GET,POST,PUT,PATCH,DELETE}
    Set request method

-e ENDPOINT, --endpoint ENDPOINT
    Set endpoint of request

-p PARAMS [PARAMS ...], --params PARAMS [PARAMS ...]
    Set params of request

--headers HEADERS [HEADERS ...]
    Set headers of request

-b BODY [BODY ...], --body BODY [BODY ...]
    Set body of request
--tree
    Set Tree view mode
-r, --raw
    Set Raw view mode
--pretty
    Set Pretty view mode
-y, --yaml
    Set Yaml view mode

Authors: 
Ihor Anikeev (CLI, Data Base ) - ianikeev@student.ucode.world 
Sergey Tsykhonia (requests, logger) - stsykhonia@student.ucode.world 
Alexander Lapatan (GUI Dark theme)- alapatan@student.ucode.world
Mikhailo Lytovchenko (Presentation)- mlytovchen@student.ucode.world



